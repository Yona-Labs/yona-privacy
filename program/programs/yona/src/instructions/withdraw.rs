use anchor_lang::prelude::*;
use anchor_lang::system_program;
use ark_ff::PrimeField;
use ark_bn254::Fr;
use light_hasher::Poseidon;
use anchor_spl::token_interface::{
    Mint, TokenAccount, TokenInterface,
    transfer_checked, close_account, TransferChecked, CloseAccount,
};
use anchor_spl::token::spl_token::native_mint;

use crate::merkle_tree::MerkleTree;
use crate::state::{MerkleTreeAccount, GlobalConfig};
use crate::types::{CompressedProof, ExtData, ExtDataMinified, CommitmentData, WithdrawEvent};
use crate::ErrorCode;
use crate::utils::{verify_compressed_proof, VERIFYING_KEY};
use crate::utils;
use crate::light::create_light_nullifiers;
use light_sdk::instruction::{PackedAddressTreeInfo, ValidityProof};



#[derive(Accounts)]
#[instruction(
    proof: CompressedProof, 
    ext_data_minified: ExtDataMinified, 
    encrypted_output: Vec<u8>,
    light_proof: ValidityProof,
    nullifier0_address_tree_info: PackedAddressTreeInfo,
    nullifier1_address_tree_info: PackedAddressTreeInfo,
    output_state_tree_index: u8
)]
pub struct Withdraw<'info> {
    #[account(
        mut,
        seeds = [b"merkle_tree"],
        bump = tree_account.load()?.bump
    )]
    pub tree_account: AccountLoader<'info, MerkleTreeAccount>,

    #[account(
        seeds = [b"global_config"],
        bump
    )]
    pub global_config: Box<Account<'info, GlobalConfig>>,
    
    pub input_mint: Box<InterfaceAccount<'info, Mint>>,

    #[account(mut,
        associated_token::mint = input_mint,  
        associated_token::authority = global_config,
        associated_token::token_program = token_program,
    )]
    pub reserve_token_account: Box<InterfaceAccount<'info, TokenAccount>>,

    /// CHECK: user should be able to receive withdrawals to any types of accounts
    #[account(mut)]
    pub recipient: UncheckedAccount<'info>,
    
    /// CHECK: authority will be validated in handler based on token type
    #[account(mut)]
    pub recipient_token_account: Box<InterfaceAccount<'info, TokenAccount>>,

    /// CHECK: user should be able to send fees to any types of accounts
    #[account(mut)]
    pub fee_recipient_account: UncheckedAccount<'info>,

    #[account(mut)]
    pub relayer: Signer<'info>,
    
    pub system_program: Program<'info, System>,
    /// Token program - supports both Token and Token-2022 programs
    pub token_program: Interface<'info, TokenInterface>,
    // Remaining accounts for Light Protocol:
    // [light_system_program, registered_program_pda, account_compression_authority, 
    //  account_compression_program, system_program, address_tree, address_queue, output_state_tree, ...]
}


pub fn handler<'info>(
    ctx: Context<'_, '_, '_, 'info, Withdraw<'info>>, 
    proof: CompressedProof, 
    ext_data_minified: ExtDataMinified, 
    encrypted_output: Vec<u8>,
    light_proof: ValidityProof,
    nullifier0_address_tree_info: PackedAddressTreeInfo,
    nullifier1_address_tree_info: PackedAddressTreeInfo,
    output_state_tree_index: u8,
) -> Result<()> {
    let tree_account = &mut ctx.accounts.tree_account.load_mut()?;
    let global_config = &ctx.accounts.global_config;

    // Reconstruct full ExtData from minified version and context accounts
    let recipient_key = ctx.accounts.recipient.key();
    
    let ext_data = ExtData::from_minified(
        &recipient_key,
        &ctx.accounts.fee_recipient_account.key(),
        ext_data_minified,
    );

    // Check if proof.root is in the tree_account's proof history
    require!(
        MerkleTree::is_known_root(&tree_account, proof.root),
        ErrorCode::UnknownRoot
    );

    // Check if the ext_data hashes to the same ext_data in the proof
    let calculated_ext_data_hash = utils::calculate_complete_ext_data_hash(
        ext_data.recipient,
        ext_data.ext_amount,
        &encrypted_output,
        ext_data.fee,
        ext_data.fee_recipient,
        ctx.accounts.input_mint.key(),
        ctx.accounts.input_mint.key(),
    )?;
    require!(
        Fr::from_le_bytes_mod_order(&calculated_ext_data_hash) == Fr::from_be_bytes_mod_order(&proof.ext_data_hash),
        ErrorCode::ExtDataHashMismatch
    );

    // For single-token transactions, only publicAmount0 is used
    // The circuit validates that both mint addresses match and balance equations hold
    require!(
        utils::check_public_amount(ext_data.ext_amount, ext_data.fee, proof.public_amount0),
        ErrorCode::InvalidPublicAmountData
    );
    require!(proof.public_amount1 == [0; 32], ErrorCode::InvalidPublicAmountData); // publicAmount1 must be zero in single-token SOL mode
    
    let ext_amount = ext_data.ext_amount;
    let fee = ext_data.fee;

    // Validate fee calculation using utility function
    utils::validate_fee(
        ext_amount,
        fee,
        global_config.deposit_fee_rate,
        global_config.withdrawal_fee_rate,
        global_config.fee_error_margin,
    )?;

    require!(verify_compressed_proof(proof.clone(), VERIFYING_KEY, ctx.accounts.input_mint.key(), ctx.accounts.input_mint.key()), ErrorCode::InvalidProof);
    require!(ext_amount < 0, ErrorCode::InvalidExtAmount);

    // Create Light Protocol nullifier compressed accounts
    create_light_nullifiers(
        ctx.accounts.relayer.as_ref(),
        ctx.remaining_accounts,
        &proof.input_nullifiers,
        light_proof,
        nullifier0_address_tree_info,
        nullifier1_address_tree_info,
        output_state_tree_index,
    )?;

    // For withdrawals, ext_amount is negative, so we need to negate it
    let withdrawal_amount = ext_amount.checked_neg()
        .ok_or(ErrorCode::ArithmeticOverflow)?;
    
    let withdrawal_amount_u64 = withdrawal_amount as u64;

    // Ensure reserve has enough balance
    require!(
        ctx.accounts.reserve_token_account.amount >= withdrawal_amount_u64,
        ErrorCode::InsufficientFundsForWithdrawal
    );

    // Create PDA signer seeds for the global_config account
    let global_config_seeds = &[
        b"global_config".as_ref(),
        &[global_config.bump],
    ];
    let signer_seeds = &[&global_config_seeds[..]];

    // Get decimals from mint for transfer_checked
    let decimals = ctx.accounts.input_mint.decimals;
    
    // Transfer fee first because we may destroy token account for WSOL
    if fee > 0 {
        let fee_transfer_ctx = CpiContext::new_with_signer(
            ctx.accounts.token_program.to_account_info(),
            TransferChecked {
                from: ctx.accounts.reserve_token_account.to_account_info(),
                mint: ctx.accounts.input_mint.to_account_info(),
                to: ctx.accounts.fee_recipient_account.to_account_info(),
                authority: ctx.accounts.global_config.to_account_info(),
            },
            signer_seeds,
        );
        transfer_checked(fee_transfer_ctx, fee, decimals)?;
    }

    // Check if the mint is native SOL (Wrapped SOL)
    let is_native_sol = native_mint::ID == ctx.accounts.input_mint.key();

    if is_native_sol {
        // For WSOL: validate that recipient_token_account authority is relayer
        require!(
            ctx.accounts.recipient_token_account.owner == ctx.accounts.relayer.key(),
            ErrorCode::Unauthorized
        );

        // For WSOL: transfer tokens, close account to relayer, then relayer sends SOL to recipient
        
        // Step 1: Transfer WSOL tokens from reserve to recipient token account
        let transfer_ctx = CpiContext::new_with_signer(
            ctx.accounts.token_program.to_account_info(),
            TransferChecked {
                from: ctx.accounts.reserve_token_account.to_account_info(),
                mint: ctx.accounts.input_mint.to_account_info(),
                to: ctx.accounts.recipient_token_account.to_account_info(),
                authority: ctx.accounts.global_config.to_account_info(),
            },
            signer_seeds,
        );
        transfer_checked(transfer_ctx, withdrawal_amount_u64, decimals)?;

        // Step 2: Close the recipient WSOL account to relayer
        // ALL lamports (rent + WSOL balance) go to relayer
        let close_ctx = CpiContext::new(
            ctx.accounts.token_program.to_account_info(),
            CloseAccount {
                account: ctx.accounts.recipient_token_account.to_account_info(),
                destination: ctx.accounts.relayer.to_account_info(),
                authority: ctx.accounts.relayer.to_account_info(),
            },
        );
        close_account(close_ctx)?;

        // Step 3: Relayer transfers SOL to recipient
        let transfer_sol_ctx = CpiContext::new(
            ctx.accounts.system_program.to_account_info(),
            system_program::Transfer {
                from: ctx.accounts.relayer.to_account_info(),
                to: ctx.accounts.recipient.to_account_info(),
            },
        );
        system_program::transfer(transfer_sol_ctx, withdrawal_amount_u64)?;
    } else {
        // For regular SPL/Token-2022 tokens: validate that recipient_token_account authority is recipient
        require!(
            ctx.accounts.recipient_token_account.owner == ctx.accounts.recipient.key(),
            ErrorCode::Unauthorized
        );

        // For regular SPL/Token-2022 tokens: transfer using transfer_checked
        let transfer_ctx = CpiContext::new_with_signer(
            ctx.accounts.token_program.to_account_info(),
            TransferChecked {
                from: ctx.accounts.reserve_token_account.to_account_info(),
                mint: ctx.accounts.input_mint.to_account_info(),
                to: ctx.accounts.recipient_token_account.to_account_info(),
                authority: ctx.accounts.global_config.to_account_info(),
            },
            signer_seeds,
        );
        transfer_checked(transfer_ctx, withdrawal_amount_u64, decimals)?;
    }


    let next_index_to_insert = tree_account.next_index;
    MerkleTree::append::<Poseidon>(proof.output_commitments[0], tree_account)?;
    MerkleTree::append::<Poseidon>(proof.output_commitments[1], tree_account)?;

    emit!(CommitmentData {
        index: next_index_to_insert,
        commitment0: proof.output_commitments[0],
        commitment1: proof.output_commitments[1],
        encrypted_output: encrypted_output.to_vec(),
    });

    emit!(WithdrawEvent {
        output_mint: ctx.accounts.input_mint.key(),
        amount: withdrawal_amount_u64,
    });
    
    Ok(())
}
