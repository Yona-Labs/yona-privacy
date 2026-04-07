use anchor_lang::prelude::*;
use light_hasher::Poseidon;

use crate::merkle_tree::MerkleTree;
use crate::state::{MerkleTreeAccount, PrivateAssetConfig};
use crate::types::{CommitmentData, CreateAssetEvent};
use crate::ErrorCode;


#[derive(Accounts)]
#[instruction(
    mint: Pubkey,
    amount: u64,
    output_commitments: [[u8; 32]; 2],
    encrypted_output: Vec<u8>,
)]
pub struct CreateAsset<'info> {
    #[account(
        mut,
        seeds = [b"merkle_tree"],
        bump = tree_account.load()?.bump
    )]
    pub tree_account: AccountLoader<'info, MerkleTreeAccount>,

    #[account(
        seeds = [b"private_asset", mint.as_ref()],
        bump = private_asset_config.bump,
        constraint = private_asset_config.admin == signer.key() @ ErrorCode::Unauthorized,
    )]
    pub private_asset_config: Account<'info, PrivateAssetConfig>,

    #[account(mut)]
    pub signer: Signer<'info>,

    pub system_program: Program<'info, System>,
}

/// Creates a compliant asset: appends UTXO commitments to the merkle tree
/// without any token operations. Tokens are minted on withdraw (and burned on deposit).
/// Only the admin of the private asset can call this.
pub fn handler(
    ctx: Context<CreateAsset>,
    mint: Pubkey,
    amount: u64,
    output_commitments: [[u8; 32]; 2],
    encrypted_output: Vec<u8>,
) -> Result<()> {
    let tree_account = &mut ctx.accounts.tree_account.load_mut()?;

    require!(amount > 0, ErrorCode::InvalidExtAmount);

    // Append both commitments to the merkle tree
    let next_index = tree_account.next_index;
    MerkleTree::append::<Poseidon>(output_commitments[0], tree_account)?;
    MerkleTree::append::<Poseidon>(output_commitments[1], tree_account)?;

    // Emit CommitmentData — indexer already listens for this event
    emit!(CommitmentData {
        index: next_index,
        commitment0: output_commitments[0],
        commitment1: output_commitments[1],
        encrypted_output: encrypted_output.to_vec(),
    });

    emit!(CreateAssetEvent {
        mint,
        amount,
    });

    Ok(())
}
