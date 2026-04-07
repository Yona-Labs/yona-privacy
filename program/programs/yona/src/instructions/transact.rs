use anchor_lang::prelude::*;
use ark_ff::PrimeField;
use ark_bn254::Fr;
use light_hasher::Poseidon;

use crate::merkle_tree::MerkleTree;
use crate::state::{MerkleTreeAccount, GlobalConfig};
use crate::types::{CompressedProof, ExtDataMinified, CommitmentData, TransferEvent};
use crate::ErrorCode;
use crate::utils::{verify_compressed_proof, VERIFYING_KEY};
use crate::utils;
use crate::light::create_light_nullifiers;
use light_sdk::instruction::{PackedAddressTreeInfo, ValidityProof};
use anchor_spl::token_interface::Mint;


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
pub struct Transact<'info> {
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

    /// CHECK: used only for extDataHash calculation, no tokens are transferred
    pub recipient_account: UncheckedAccount<'info>,

    /// CHECK: used only for extDataHash calculation, no tokens are transferred
    pub fee_recipient_account: UncheckedAccount<'info>,

    #[account(mut)]
    pub user: Signer<'info>,

    pub system_program: Program<'info, System>,
    // Remaining accounts for Light Protocol:
    // [light_system_program, registered_program_pda, account_compression_authority,
    //  account_compression_program, system_program, address_tree, address_queue, output_state_tree, ...]
}

pub fn handler<'info>(
    ctx: Context<'_, '_, '_, 'info, Transact<'info>>,
    proof: CompressedProof,
    ext_data_minified: ExtDataMinified,
    encrypted_output: Vec<u8>,
    light_proof: ValidityProof,
    nullifier0_address_tree_info: PackedAddressTreeInfo,
    nullifier1_address_tree_info: PackedAddressTreeInfo,
    output_state_tree_index: u8,
) -> Result<()> {
    let tree_account = &mut ctx.accounts.tree_account.load_mut()?;

    // Transfer must have ext_amount = 0 and fee = 0
    require!(ext_data_minified.ext_amount == 0, ErrorCode::InvalidExtAmount);
    require!(ext_data_minified.fee == 0, ErrorCode::InvalidFee);

    // Check if proof.root is in the tree_account's root history
    require!(
        MerkleTree::is_known_root(&tree_account, proof.root),
        ErrorCode::UnknownRoot
    );

    // Both public amounts must be zero (no tokens enter or leave the pool)
    require!(proof.public_amount0 == [0; 32], ErrorCode::InvalidPublicAmountData);
    require!(proof.public_amount1 == [0; 32], ErrorCode::InvalidPublicAmountData);

    // Check if the ext_data hashes to the same ext_data in the proof
    let calculated_ext_data_hash = utils::calculate_complete_ext_data_hash(
        ctx.accounts.recipient_account.key(),
        ext_data_minified.ext_amount,
        &encrypted_output,
        ext_data_minified.fee,
        ctx.accounts.fee_recipient_account.key(),
        ctx.accounts.input_mint.key(),
        ctx.accounts.input_mint.key(),
    )?;
    require!(
        Fr::from_le_bytes_mod_order(&calculated_ext_data_hash) == Fr::from_be_bytes_mod_order(&proof.ext_data_hash),
        ErrorCode::ExtDataHashMismatch
    );

    // Verify the ZK proof
    msg!("verifying transfer proof");
    require!(
        verify_compressed_proof(
            proof.clone(),
            VERIFYING_KEY,
            ctx.accounts.input_mint.key(),
            ctx.accounts.input_mint.key()
        ),
        ErrorCode::InvalidProof
    );
    msg!("transfer proof verified");

    // Create Light Protocol nullifier compressed accounts (double-spend prevention)
    create_light_nullifiers(
        ctx.accounts.user.as_ref(),
        ctx.remaining_accounts,
        &proof.input_nullifiers,
        light_proof,
        nullifier0_address_tree_info,
        nullifier1_address_tree_info,
        output_state_tree_index,
    )?;

    // Append output commitments to the Merkle tree
    let next_index_to_insert = tree_account.next_index;
    MerkleTree::append::<Poseidon>(proof.output_commitments[0], tree_account)?;
    MerkleTree::append::<Poseidon>(proof.output_commitments[1], tree_account)?;

    emit!(CommitmentData {
        index: next_index_to_insert,
        commitment0: proof.output_commitments[0],
        commitment1: proof.output_commitments[1],
        encrypted_output: encrypted_output.to_vec(),
    });

    emit!(TransferEvent {
        input_mint: ctx.accounts.input_mint.key(),
    });

    Ok(())
}
