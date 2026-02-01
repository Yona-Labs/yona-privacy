use anchor_lang::prelude::*;

// Constants
pub const MERKLE_TREE_HEIGHT: u8 = 26;
pub const ROOT_HISTORY_SIZE: usize = 100;

#[account]
pub struct TreeTokenAccount {
    pub authority: Pubkey,
    pub bump: u8,
}

#[account]
pub struct GlobalConfig {
    pub authority: Pubkey,
    pub deposit_fee_rate: u16,    // basis points (0-10000, where 10000 = 100%)
    pub withdrawal_fee_rate: u16, // basis points (0-10000, where 10000 = 100%)
    pub fee_error_margin: u16,    // basis points (0-10000, where 10000 = 100%)
    pub bump: u8,
}

#[account]
pub struct NullifierAccount {
    /// This account's existence indicates that the nullifier has been used.
    /// No fields needed other than bump for PDA verification.
    pub bump: u8,
}

#[account(zero_copy)]
pub struct MerkleTreeAccount {
    pub authority: Pubkey,
    pub next_index: u64,
    pub subtrees: [[u8; 32]; MERKLE_TREE_HEIGHT as usize],
    pub root: [u8; 32],
    pub root_history: [[u8; 32]; ROOT_HISTORY_SIZE],
    pub root_index: u64,
    pub max_deposit_amount: u64,
    pub height: u8,
    pub root_history_size: u8,
    pub bump: u8,
    // The pub _padding: [u8; 5] is needed because of the #[account(zero_copy)] attribute.
    pub _padding: [u8; 5],
}

