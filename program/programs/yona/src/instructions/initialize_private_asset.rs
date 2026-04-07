use anchor_lang::prelude::*;

use crate::state::PrivateAssetConfig;

#[derive(Accounts)]
#[instruction(mint: Pubkey)]
pub struct InitializePrivateAsset<'info> {
    #[account(
        init,
        payer = admin,
        space = 8 + std::mem::size_of::<PrivateAssetConfig>(),
        seeds = [b"private_asset", mint.as_ref()],
        bump
    )]
    pub private_asset_config: Account<'info, PrivateAssetConfig>,

    #[account(mut)]
    pub admin: Signer<'info>,

    pub system_program: Program<'info, System>,
}

pub fn handler(ctx: Context<InitializePrivateAsset>, mint: Pubkey) -> Result<()> {
    let config = &mut ctx.accounts.private_asset_config;
    config.admin = ctx.accounts.admin.key();
    config.mint = mint;
    config.bump = ctx.bumps.private_asset_config;
    Ok(())
}
