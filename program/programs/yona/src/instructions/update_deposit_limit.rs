use anchor_lang::prelude::*;

/**
 * Update the maximum deposit amount limit. Only the authority can call this.
 */
pub fn handler(ctx: Context<crate::UpdateDepositLimit>, new_limit: u64) -> Result<()> {
    let tree_account = &mut ctx.accounts.tree_account.load_mut()?;
    
    tree_account.max_deposit_amount = new_limit;
    
    msg!("Deposit limit updated to: {} lamports", new_limit);
    Ok(())
}

