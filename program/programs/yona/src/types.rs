use anchor_lang::prelude::*;

#[event]
pub struct CommitmentData {
    pub index: u64,
    pub commitment0: [u8; 32],
    pub commitment1: [u8; 32],
    pub encrypted_output: Vec<u8>,
}

#[event]
pub struct DepositEvent {
    pub input_mint: Pubkey,
    pub amount: u64,
}

#[event]
pub struct WithdrawEvent {
    pub output_mint: Pubkey,
    pub amount: u64,
}

#[event]
pub struct SwapEvent {
    pub input_mint: Pubkey,
    pub output_mint: Pubkey,
    pub input_amount: u64,
    pub output_amount: u64,
}


// all public inputs needs to be in big endian format
// Compressed proof format - saves transaction size
#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct CompressedProof {
    pub proof_a: [u8; 32],
    pub proof_b: [u8; 64],
    pub proof_c: [u8; 32],
    pub root: [u8; 32],
    pub public_amount0: [u8; 32],
    pub public_amount1: [u8; 32],
    pub ext_data_hash: [u8; 32],
    pub input_nullifiers: [[u8; 32]; 2],
    pub output_commitments: [[u8; 32]; 2],
}


#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct ExtData {
    pub recipient: Pubkey,
    pub ext_amount: i64,
    pub fee: u64,
    pub fee_recipient: Pubkey,
}


#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct ExtDataMinified {
    pub ext_amount: i64,
    pub fee: u64,
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct SwapExtDataMinified {
    pub ext_amount: i64,
    pub ext_min_amount_out: i64,
    pub fee: u64,
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct SwapExtData { // TODO ADD JUP DATA
    pub ext_amount: i64,
    pub ext_min_amount_out: i64,
    pub fee: u64,
    pub fee_recipient: Pubkey,
}

impl ExtData {
    pub fn from_minified<'info>(
        recipient: &Pubkey,
        fee_recipient: &Pubkey,
        minified: ExtDataMinified,
    ) -> Self {
        Self {
            recipient: *recipient,
            ext_amount: minified.ext_amount,
            fee: minified.fee,
            fee_recipient: *fee_recipient,
        }
    }
}

impl SwapExtData {
    pub fn from_minified<'info>(
        fee_recipient: &Pubkey, 
        minified: SwapExtDataMinified,
    ) -> Self {
        Self {
            ext_amount: minified.ext_amount,
            ext_min_amount_out: minified.ext_min_amount_out,
            fee: minified.fee,
            fee_recipient: *fee_recipient,  
        }
    }
}

