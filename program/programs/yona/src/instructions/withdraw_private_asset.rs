use anchor_lang::prelude::*;
use ark_ff::PrimeField;
use ark_bn254::Fr;
use light_hasher::Poseidon;
use anchor_spl::token_interface::{
    Mint, TokenAccount, TokenInterface,
    mint_to, MintTo,
};

use crate::merkle_tree::MerkleTree;
use crate::state::{MerkleTreeAccount, GlobalConfig, PrivateAssetConfig};
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
pub struct WithdrawPrivateAsset<'info> {
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

    #[account(
        seeds = [b"private_asset", input_mint.key().as_ref()],
        bump = private_asset_config.bump,
    )]
    pub private_asset_config: Account<'info, PrivateAssetConfig>,

    #[account(mut)]
    pub input_mint: Box<InterfaceAccount<'info, Mint>>,

    /// CHECK: user should be able to receive withdrawals to any types of accounts
    #[account(mut)]
    pub recipient: UncheckedAccount<'info>,

    #[account(mut)]
    pub recipient_token_account: Box<InterfaceAccount<'info, TokenAccount>>,

    /// CHECK: user should be able to send fees to any types of accounts
    #[account(mut)]
    pub fee_recipient_account: UncheckedAccount<'info>,

    #[account(mut)]
    pub relayer: Signer<'info>,

    pub system_program: Program<'info, System>,
    pub token_program: Interface<'info, TokenInterface>,
}

pub fn handler<'info>(
    ctx: Context<'_, '_, '_, 'info, WithdrawPrivateAsset<'info>>,
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

    let recipient_key = ctx.accounts.recipient.key();

    let ext_data = ExtData::from_minified(
        &recipient_key,
        &ctx.accounts.fee_recipient_account.key(),
        ext_data_minified,
    );

    require!(
        MerkleTree::is_known_root(&tree_account, proof.root),
        ErrorCode::UnknownRoot
    );

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

    require!(
        utils::check_public_amount(ext_data.ext_amount, ext_data.fee, proof.public_amount0),
        ErrorCode::InvalidPublicAmountData
    );
    require!(proof.public_amount1 == [0; 32], ErrorCode::InvalidPublicAmountData);

    let ext_amount = ext_data.ext_amount;
    let fee = ext_data.fee;

    utils::validate_fee(
        ext_amount,
        fee,
        global_config.deposit_fee_rate,
        global_config.withdrawal_fee_rate,
        global_config.fee_error_margin,
    )?;

    require!(
        verify_compressed_proof(
            proof.clone(),
            VERIFYING_KEY,
            ctx.accounts.input_mint.key(),
            ctx.accounts.input_mint.key()
        ),
        ErrorCode::InvalidProof
    );
    require!(ext_amount < 0, ErrorCode::InvalidExtAmount);

    create_light_nullifiers(
        ctx.accounts.relayer.as_ref(),
        ctx.remaining_accounts,
        &proof.input_nullifiers,
        light_proof,
        nullifier0_address_tree_info,
        nullifier1_address_tree_info,
        output_state_tree_index,
    )?;

    let withdrawal_amount = ext_amount.checked_neg()
        .ok_or(ErrorCode::ArithmeticOverflow)?;
    let withdrawal_amount_u64 = withdrawal_amount as u64;

    // Mint tokens to recipient using global_config as mint authority
    let global_config_seeds = &[
        b"global_config".as_ref(),
        &[global_config.bump],
    ];
    let signer_seeds = &[&global_config_seeds[..]];

    let mint_ctx = CpiContext::new_with_signer(
        ctx.accounts.token_program.to_account_info(),
        MintTo {
            mint: ctx.accounts.input_mint.to_account_info(),
            to: ctx.accounts.recipient_token_account.to_account_info(),
            authority: ctx.accounts.global_config.to_account_info(),
        },
        signer_seeds,
    );
    mint_to(mint_ctx, withdrawal_amount_u64)?;

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
