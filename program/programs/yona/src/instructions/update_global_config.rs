use anchor_lang::prelude::*;
use crate::ErrorCode;

/**
 * Update global configuration. Only the authority can call this.
 */
pub fn handler(
    ctx: Context<crate::UpdateGlobalConfig>, 
    deposit_fee_rate: Option<u16>,
    withdrawal_fee_rate: Option<u16>,
    fee_error_margin: Option<u16>
) -> Result<()> {
    let global_config = &mut ctx.accounts.global_config;
    
    if let Some(deposit_rate) = deposit_fee_rate {
        require!(deposit_rate <= 10000, ErrorCode::InvalidFeeRate);
        global_config.deposit_fee_rate = deposit_rate;
        msg!("Deposit fee rate updated to: {} basis points", deposit_rate);
    }
    
    if let Some(withdrawal_rate) = withdrawal_fee_rate {
        require!(withdrawal_rate <= 10000, ErrorCode::InvalidFeeRate);
        global_config.withdrawal_fee_rate = withdrawal_rate;
        msg!("Withdrawal fee rate updated to: {} basis points", withdrawal_rate);
    }
    
    if let Some(fee_error_margin_val) = fee_error_margin {
        require!(fee_error_margin_val <= 10000, ErrorCode::InvalidFeeRate);
        global_config.fee_error_margin = fee_error_margin_val;
        msg!("Fee error margin updated to: {} basis points", fee_error_margin_val);
    }
    
    Ok(())
}

