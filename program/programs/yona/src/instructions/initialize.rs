use anchor_lang::prelude::*;
use crate::merkle_tree::MerkleTree;
use crate::state::MERKLE_TREE_HEIGHT;
use crate::ADMIN_PUBKEY;
use crate::ErrorCode;
use light_hasher::Poseidon;

pub fn handler(ctx: Context<crate::Initialize>) -> Result<()> { 
    if let Some(admin_key) = ADMIN_PUBKEY {
        require!(ctx.accounts.authority.key().eq(&admin_key), ErrorCode::Unauthorized);
    } // TODO: remove admin key for testing
    
    let tree_account = &mut ctx.accounts.tree_account.load_init()?;
    tree_account.authority = ctx.accounts.authority.key();
    tree_account.next_index = 0;
    tree_account.root_index = 0;
    tree_account.bump = ctx.bumps.tree_account;
    tree_account.max_deposit_amount = 1_000_000_000_000; // 1000 SOL default limit
    tree_account.height = MERKLE_TREE_HEIGHT; // Hardcoded height
    tree_account.root_history_size = 100; // Hardcoded root history size

    MerkleTree::initialize::<Poseidon>(tree_account)?;
    
    // Initialize global config
    let global_config = &mut ctx.accounts.global_config;
    global_config.authority = ctx.accounts.authority.key();
    global_config.deposit_fee_rate = 0; // 0% - Free deposits
    global_config.withdrawal_fee_rate = 30; // 0.3% (30 basis points)
    global_config.fee_error_margin = 500; // 5% (500 basis points)
    global_config.bump = ctx.bumps.global_config;
    
    msg!("Sparse Merkle Tree initialized successfully with height: {}, root history size: {}, deposit limit: {} lamports, 
        deposit fee rate: {}, withdrawal fee rate: {}, fee error margin: {}",
        MERKLE_TREE_HEIGHT, 100, tree_account.max_deposit_amount, global_config.deposit_fee_rate, global_config.withdrawal_fee_rate, global_config.fee_error_margin);
    Ok(())
}

