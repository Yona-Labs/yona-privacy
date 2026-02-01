use anchor_lang::prelude::*;
use ark_ff::PrimeField;
use ark_bn254::Fr;
use light_hasher::Poseidon;
use anchor_spl::token_interface::{
    Mint, TokenAccount, TokenInterface,
    transfer_checked, TransferChecked,
};
use anchor_lang::solana_program::program::invoke_signed;
use anchor_lang::solana_program::instruction::Instruction;

use crate::merkle_tree::MerkleTree;
use crate::state::{MerkleTreeAccount, GlobalConfig};
use crate::types::{CompressedProof, SwapExtData, SwapExtDataMinified, CommitmentData, SwapEvent};
use crate::ErrorCode;
use crate::utils::{verify_compressed_proof, VERIFYING_KEY};
use crate::utils;
use crate::light::create_light_nullifiers;
use light_sdk::instruction::{PackedAddressTreeInfo, ValidityProof};

// Number of Light Protocol accounts in remaining_accounts:
// System accounts: 8 (light_system_program, cpi_signer, registered_program_pda, 
//                      noop_program, account_compression_authority, account_compression_program,
//                      self_program, system_program)
// Tree accounts: 4 (address_tree, address_queue, output_state_tree, nullifier_queue)
// Total: 12
const NUM_LIGHT_ACCOUNTS: usize = 12;


#[derive(Accounts)]
#[instruction(
    proof: CompressedProof, 
    ext_data_minified: SwapExtDataMinified, 
    encrypted_output: Vec<u8>, 
    jupiter_swap_data: Vec<u8>,
    light_proof: ValidityProof,
    nullifier0_address_tree_info: PackedAddressTreeInfo,
    nullifier1_address_tree_info: PackedAddressTreeInfo,
    output_state_tree_index: u8
)]
pub struct Swap<'info> {
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
    pub output_mint: Box<InterfaceAccount<'info, Mint>>,

    #[account(mut,
        associated_token::mint = input_mint,  
        associated_token::authority = global_config,
        associated_token::token_program = input_token_program,
    )]
    pub reserve_token_account_input: Box<InterfaceAccount<'info, TokenAccount>>,

    #[account(mut,
        associated_token::mint = output_mint,  
        associated_token::authority = global_config,
        associated_token::token_program = output_token_program,
    )]
    pub reserve_token_account_output: Box<InterfaceAccount<'info, TokenAccount>>,

    #[account(mut)]
    /// CHECK: user should be able to send fees to any types of accounts
    pub fee_recipient_account: UncheckedAccount<'info>,

    /// Jupiter aggregator program
    /// CHECK: Jupiter program ID
    pub jupiter_program: UncheckedAccount<'info>,

    #[account(mut)]
    pub user: Signer<'info>,
    
    pub system_program: Program<'info, System>,
    /// Token program for input mint - supports both Token and Token-2022 programs
    pub input_token_program: Interface<'info, TokenInterface>,
    /// Token program for output mint - supports both Token and Token-2022 programs
    pub output_token_program: Interface<'info, TokenInterface>,
    // Remaining accounts:
    // First num_light_accounts accounts are for Light Protocol:
    //   [light_system_program, cpi_signer, registered_program_pda, noop_program,
    //    account_compression_authority, account_compression_program, self_program,
    //    system_program, address_tree, address_queue, output_state_tree, nullifier_queue]
    // Remaining accounts after num_light_accounts are for Jupiter (if used)
}



/**
 * Swap tokens from one mint to another using Jupiter aggregator.
 * 
 * User burns UTXO with mintA and creates UTXO with mintB.
 * extAmount should be 0 for pure swaps (no deposit/withdrawal).
 * 
 * Reentrant attacks are not possible, because nullifier creation is checked by Light Protocol.
 */
pub fn handler<'info>(
    ctx: Context<'_, '_, '_, 'info, Swap<'info>>, 
    proof: CompressedProof, 
    ext_data_minified: SwapExtDataMinified, 
    encrypted_output: Vec<u8>, 
    jupiter_swap_data: Vec<u8>,
    light_proof: ValidityProof,
    nullifier0_address_tree_info: PackedAddressTreeInfo,
    nullifier1_address_tree_info: PackedAddressTreeInfo,
    output_state_tree_index: u8,
) -> Result<()> {    
    let tree_account = &mut ctx.accounts.tree_account.load_mut()?;
    let global_config = &ctx.accounts.global_config;

    // Reconstruct full SwapExtData from minified version and context accounts
    let ext_data = SwapExtData::from_minified(
        &ctx.accounts.fee_recipient_account.key(),
        ext_data_minified,
    );

    // Check if proof.root is in the tree_account's proof history
    require!(
        MerkleTree::is_known_root(&tree_account, proof.root),
        ErrorCode::UnknownRoot
    );


    // Check if the ext_data hashes to the same ext_data in the proof
    let calculated_ext_data_hash = utils::calculate_swap_ext_data_hash(
        ext_data.ext_amount,
        ext_data.ext_min_amount_out,
        &encrypted_output,
        ext_data.fee,
        ext_data.fee_recipient,
        ctx.accounts.input_mint.key(),
        ctx.accounts.output_mint.key(),
    )?;
    require!(
        Fr::from_le_bytes_mod_order(&calculated_ext_data_hash) == Fr::from_be_bytes_mod_order(&proof.ext_data_hash),
        ErrorCode::ExtDataHashMismatch
    );

    // For swaps, extAmount should typically be 0 (no net deposit or withdrawal)
    // Calculate swap amounts from public amounts
    // publicAmount0 is the net change in input mint (negative for swap out)
    // publicAmount1 is the net change in output mint (positive for swap in)
    require!(ext_data.ext_amount < 0, ErrorCode::InvalidExtAmount);
    require!(ext_data.ext_min_amount_out >= 0, ErrorCode::InvalidExtAmount);

    require!(
        utils::check_public_amount(ext_data.ext_amount, ext_data.fee, proof.public_amount0),
        ErrorCode::InvalidPublicAmountData
    );
    // zero fee for swap out
    require!(
        utils::check_public_amount(ext_data.ext_min_amount_out, 0, proof.public_amount1),
        ErrorCode::InvalidPublicAmountData
    );

    let ext_amount = ext_data.ext_amount;
    let fee = ext_data.fee;

    // Validate fee calculation
    // https://docs.yona.cash/concepts/fees - we take fee from output amount. 
    // When you execute a swap with a 0.3% slippage tolerance, here's what happens:
    // You receive the minimum amount out - Your transaction is guaranteed to complete, and you'll receive at least the minimum output amount based on the slippage tolerance
    // Relayer takes the remaining tokens - Any difference between the actual swap output and the minimum amount goes to the relayer
    // Relayer absorbs the slippage risk - By taking the remaining tokens, the relayer assumes all slippage risks
    // utils::validate_fee(
    //     ext_amount,
    //     fee,
    //     global_config.deposit_fee_rate, 
    //     global_config.deposit_fee_rate,
    //     global_config.fee_error_margin,
    // )?;

    // Verify the proof with both mint addresses
    require!(
        verify_compressed_proof(
            proof.clone(), 
            VERIFYING_KEY, 
            ctx.accounts.input_mint.key(), 
            ctx.accounts.output_mint.key()
        ), 
        ErrorCode::InvalidProof
    );

    // Split remaining accounts: first NUM_LIGHT_ACCOUNTS are for Light Protocol, rest are for Jupiter
    let (light_accounts, jupiter_accounts) = ctx.remaining_accounts.split_at(NUM_LIGHT_ACCOUNTS);

    // Create Light Protocol nullifier compressed accounts
    create_light_nullifiers(
        ctx.accounts.user.as_ref(),
        light_accounts,
        &proof.input_nullifiers,
        light_proof,
        nullifier0_address_tree_info,
        nullifier1_address_tree_info,
        output_state_tree_index,
    )?;

    // Get balance before swap
    let balance_before = ctx.accounts.reserve_token_account_output.amount;

    if jupiter_swap_data.len() > 0 {
        let mut account_metas = Vec::new();
        
        // Add remaining accounts (these are the accounts needed by Jupiter)
        for account in jupiter_accounts.iter() {
            let is_signer = if *account.key == ctx.accounts.global_config.key() {
                true
            } else {
                account.is_signer
            };
            account_metas.push(anchor_lang::solana_program::instruction::AccountMeta {
                pubkey: *account.key,
                is_signer,
                is_writable: account.is_writable,
            });
        }

        // Create Jupiter instruction
        let jupiter_instruction = Instruction {
            program_id: ctx.accounts.jupiter_program.key(),
            accounts: account_metas,
            data: jupiter_swap_data,
        };
        
        // Execute Jupiter CPI
        let account_infos: Vec<AccountInfo> = jupiter_accounts.to_vec();
        let global_config_seeds = &[
            b"global_config".as_ref(),
            &[global_config.bump],
        ];
        let signer_seeds = &[&global_config_seeds[..]];

        invoke_signed(
            &jupiter_instruction,
            &account_infos,
            signer_seeds,
        )?;
        
    } else {
       return Err(ErrorCode::InvalidJupiterSwapData.into());
    }

    // Reload the output token account to get updated balance
    ctx.accounts.reserve_token_account_output.reload()?;
    let balance_after = ctx.accounts.reserve_token_account_output.amount;
    
    // Calculate actual received amount
    let actual_amount_received = balance_after.checked_sub(balance_before)
        .ok_or(ErrorCode::MathOverflow)?;
    
    // Calculate fee as difference between received and min_amount_out
    let min_amount = ext_data.ext_min_amount_out as u64;
    let calculated_fee = actual_amount_received.checked_sub(min_amount)
        .ok_or(ErrorCode::InsufficientSwapOutput)?;

    // Transfer the fee to fee recipient using transfer_checked (Token-2022 compatible)
    if calculated_fee > 0 {
        let global_config_seeds = &[
            b"global_config".as_ref(),
            &[global_config.bump],
        ];
        let signer_seeds = &[&global_config_seeds[..]];
        let output_decimals = ctx.accounts.output_mint.decimals;

        let transfer_ctx = CpiContext::new_with_signer(
            ctx.accounts.output_token_program.to_account_info(),
            TransferChecked {
                from: ctx.accounts.reserve_token_account_output.to_account_info(),
                mint: ctx.accounts.output_mint.to_account_info(),
                to: ctx.accounts.fee_recipient_account.to_account_info(),
                authority: ctx.accounts.global_config.to_account_info(),
            },
            signer_seeds,
        );
        transfer_checked(transfer_ctx, calculated_fee, output_decimals)?;
        msg!("Slippage fee: {}", calculated_fee);
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

    let input_amount = ext_amount.checked_neg()
        .ok_or(ErrorCode::ArithmeticOverflow)? as u64;

    emit!(SwapEvent {
        input_mint: ctx.accounts.input_mint.key(),
        output_mint: ctx.accounts.output_mint.key(),
        input_amount,
        output_amount: actual_amount_received,
    });
    
    Ok(())
}
