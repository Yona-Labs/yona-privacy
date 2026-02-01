use anchor_lang::prelude::*;
use ark_ff::PrimeField;
use ark_bn254::Fr;
use light_hasher::Poseidon;
use anchor_spl::token_interface::{
    Mint, TokenAccount, TokenInterface,
    transfer_checked, TransferChecked,
};

use crate::merkle_tree::MerkleTree;
use crate::state::{MerkleTreeAccount, GlobalConfig};
use crate::types::{CompressedProof, ExtData, ExtDataMinified, CommitmentData, DepositEvent};
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


pub struct Deposit<'info> {
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

    /// CHECK: user should be able to send fees to any types of accounts
    pub fee_recipient_account: UncheckedAccount<'info>,

    #[account(mut,
        associated_token::mint = input_mint,  
        associated_token::authority = user,
        associated_token::token_program = token_program,
    )]
    pub user_token_account: Box<InterfaceAccount<'info, TokenAccount>>,

    #[account(mut)]
    pub user: Signer<'info>,
    
    pub system_program: Program<'info, System>,
    /// Token program - supports both Token and Token-2022 programs
    pub token_program: Interface<'info, TokenInterface>,
    // Remaining accounts for Light Protocol:
    // [light_system_program, registered_program_pda, account_compression_authority, 
    //  account_compression_program, system_program, address_tree, address_queue, output_state_tree, ...]
}

pub fn handler<'info>(
    ctx: Context<'_, '_, '_, 'info, Deposit<'info>>, 
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
    let ext_data = ExtData::from_minified(
        &ctx.accounts.reserve_token_account.key(),
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

    // For single-token SOL transactions, only publicAmount0 is used
    require!(
        utils::check_public_amount(ext_data.ext_amount, ext_data.fee, proof.public_amount0),
        ErrorCode::InvalidPublicAmountData
    );
    require!(proof.public_amount1 == [0; 32], ErrorCode::InvalidPublicAmountData);
    
    let ext_amount = ext_data.ext_amount;
    let fee = ext_data.fee;

    // Validate fee calculation
    utils::validate_fee(
        ext_amount,
        fee,
        global_config.deposit_fee_rate,
        global_config.withdrawal_fee_rate,
        global_config.fee_error_margin,
    )?;

    // Verify the ZK proof
    msg!("verifying proof");
    require!(
        verify_compressed_proof(
            proof.clone(), 
            VERIFYING_KEY, 
            ctx.accounts.input_mint.key(), 
            ctx.accounts.input_mint.key()
        ), 
        ErrorCode::InvalidProof
    );
    msg!("proof verified");
    
    require!(ext_amount > 0, ErrorCode::InvalidExtAmount);
    let deposit_amount = ext_amount as u64;

    require!(
        deposit_amount <= tree_account.max_deposit_amount,
        ErrorCode::DepositLimitExceeded
    );

    // Create Light Protocol nullifier compressed accounts
    create_light_nullifiers(
        ctx.accounts.user.as_ref(),
        ctx.remaining_accounts,
        &proof.input_nullifiers,
        light_proof,
        nullifier0_address_tree_info,
        nullifier1_address_tree_info,
        output_state_tree_index,
    )?;

    // Get decimals from mint for transfer_checked
    let decimals = ctx.accounts.input_mint.decimals;

    // Transfer tokens from user to reserve using transfer_checked (Token-2022 compatible)
    let transfer_ctx = CpiContext::new(
        ctx.accounts.token_program.to_account_info(),
        TransferChecked {
            from: ctx.accounts.user_token_account.to_account_info(),
            mint: ctx.accounts.input_mint.to_account_info(),
            to: ctx.accounts.reserve_token_account.to_account_info(),
            authority: ctx.accounts.user.to_account_info(),
        },
    );
    transfer_checked(transfer_ctx, deposit_amount, decimals)?;
    
    // Transfer fee if applicable
    if fee > 0 {
        let transfer_ctx = CpiContext::new(
            ctx.accounts.token_program.to_account_info(),
            TransferChecked {
                from: ctx.accounts.user_token_account.to_account_info(),
                mint: ctx.accounts.input_mint.to_account_info(),
                to: ctx.accounts.fee_recipient_account.to_account_info(),
                authority: ctx.accounts.user.to_account_info(),
            },
        );
        transfer_checked(transfer_ctx, fee, decimals)?;
    }

    // Append commitments to the merkle tree
    let next_index_to_insert = tree_account.next_index;
    MerkleTree::append::<Poseidon>(proof.output_commitments[0], tree_account)?;
    MerkleTree::append::<Poseidon>(proof.output_commitments[1], tree_account)?;

    emit!(CommitmentData {
        index: next_index_to_insert,
        commitment0: proof.output_commitments[0],
        commitment1: proof.output_commitments[1],
        encrypted_output: encrypted_output.to_vec(),
    });

    emit!(DepositEvent {
        input_mint: ctx.accounts.input_mint.key(),
        amount: deposit_amount,
    });

    Ok(())
}
