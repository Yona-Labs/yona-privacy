use crate::types::CompressedProof;
use crate::groth16::{Groth16Verifier, Groth16Verifyingkey};
use crate::ErrorCode;
use ark_bn254::Fr;
use ark_ff::PrimeField;
use anchor_lang::prelude::*;
use anchor_lang::solana_program::hash::hash;
use groth16_solana::decompression::{decompress_g1, decompress_g2};

pub const VERIFYING_KEY: Groth16Verifyingkey = Groth16Verifyingkey {
	nr_pubinputs: 10,

	vk_alpha_g1: [
		45,77,154,167,227,2,217,223,65,116,157,85,7,148,157,5,219,234,51,251,177,108,100,59,34,245,153,162,190,109,242,226,
		20,190,221,80,60,55,206,176,97,216,236,96,32,159,227,69,206,137,131,10,25,35,3,1,240,118,202,255,0,77,25,38,
	],

	vk_beta_g2: [
		9,103,3,47,203,247,118,209,175,201,133,248,136,119,241,130,211,132,128,166,83,242,222,202,169,121,76,188,59,243,6,12,
		14,24,120,71,173,76,121,131,116,208,214,115,43,245,1,132,125,214,139,192,224,113,36,30,2,19,188,127,193,61,183,171,
		48,76,251,209,224,138,112,74,153,245,232,71,217,63,140,60,170,253,222,196,107,122,13,55,157,166,154,77,17,35,70,167,
		23,57,193,177,164,87,168,199,49,49,35,210,77,47,145,146,248,150,183,198,62,234,5,169,213,127,6,84,122,208,206,200,
	],

	vk_gamma_g2: [
		25,142,147,147,146,13,72,58,114,96,191,183,49,251,93,37,241,170,73,51,53,169,231,18,151,228,133,183,174,243,18,194,
		24,0,222,239,18,31,30,118,66,106,0,102,94,92,68,121,103,67,34,212,247,94,218,221,70,222,189,92,217,146,246,237,
		9,6,137,208,88,95,240,117,236,158,153,173,105,12,51,149,188,75,49,51,112,179,142,243,85,172,218,220,209,34,151,91,
		18,200,94,165,219,140,109,235,74,171,113,128,141,203,64,143,227,209,231,105,12,67,211,123,76,230,204,1,102,250,125,170,
	],

	vk_delta_g2: [
		14,158,205,113,196,210,188,9,178,153,238,14,86,48,127,103,50,91,78,215,94,230,37,191,198,14,167,30,230,213,45,189,
		19,137,13,98,149,160,221,76,64,62,188,155,6,214,188,155,215,121,177,50,73,173,198,254,231,206,243,126,15,22,245,149,
		21,98,129,170,72,68,155,122,74,218,94,45,166,91,31,225,178,127,228,118,203,26,30,247,229,100,5,172,76,53,39,239,
		18,6,133,66,115,33,102,82,54,253,222,59,150,202,38,106,72,64,45,142,75,251,224,129,24,127,91,65,191,88,84,161,
	],

	vk_ic: &[
		[
			28,160,211,185,155,90,54,7,95,51,153,240,123,97,66,218,240,14,44,43,124,70,226,114,158,134,114,39,30,49,2,232,
			14,27,110,117,2,37,141,106,131,252,70,229,44,219,37,54,68,95,164,251,82,66,114,17,253,158,197,85,91,42,107,87,
		],
		[
			8,6,156,235,121,185,40,198,109,112,136,171,113,12,195,70,82,83,197,185,201,182,41,189,247,112,81,220,173,125,22,18,
			17,110,104,146,17,115,38,75,52,100,156,122,69,176,81,185,124,74,96,194,126,198,88,19,159,90,168,120,46,251,56,110,
		],
		[
			46,201,177,63,228,199,126,43,118,63,11,10,56,182,231,118,55,198,42,170,197,100,208,8,76,171,222,83,48,180,231,124,
			40,253,138,95,161,118,249,65,44,15,38,191,192,184,147,50,213,187,202,135,14,81,13,177,157,221,59,220,139,192,68,222,
		],
		[
			7,81,28,116,79,237,164,254,33,101,158,58,119,70,201,164,48,60,216,23,243,247,115,132,18,96,55,188,118,21,94,227,
			35,101,37,159,29,226,38,107,237,229,125,164,186,218,173,138,210,193,203,143,2,58,229,215,63,134,78,20,156,105,40,254,
		],
		[
			13,68,46,44,162,38,79,29,248,24,139,116,125,237,22,175,43,192,111,11,226,2,183,61,248,1,146,140,228,98,198,119,
			28,49,98,178,28,147,29,246,104,229,181,82,232,97,171,182,76,120,242,120,174,133,127,0,3,20,117,109,241,32,105,1,
		],
		[
			9,255,9,228,46,234,53,124,181,189,168,24,91,47,238,99,166,166,89,55,108,44,128,68,68,166,26,47,112,104,153,199,
			26,158,9,181,5,189,217,9,65,123,236,188,108,100,166,212,185,215,108,187,134,57,21,13,38,0,155,247,121,218,54,141,
		],
		[
			44,120,239,95,204,75,16,74,148,184,136,121,140,78,106,29,102,193,166,210,103,51,25,144,220,49,101,206,244,75,253,241,
			27,128,52,74,56,147,237,67,119,186,214,40,31,53,28,141,248,188,91,192,176,173,60,108,158,200,208,11,109,202,25,30,
		],
		[
			8,74,201,62,231,91,38,108,145,51,76,37,84,160,202,182,173,204,124,112,120,178,141,172,73,109,49,207,54,211,178,227,
			22,245,79,48,56,88,93,185,235,120,2,140,197,161,59,109,133,215,15,110,228,107,19,40,196,168,124,164,162,214,81,74,
		],
		[
			6,191,131,211,13,217,96,250,122,243,27,192,234,216,82,64,18,255,200,239,183,79,217,219,151,71,56,255,105,37,229,220,
			25,134,92,70,212,18,55,24,250,164,214,100,128,45,191,239,169,39,195,71,24,76,224,73,187,122,120,8,78,143,12,177,
		],
		[
			31,119,243,141,247,217,36,137,166,67,255,96,90,136,115,99,113,102,205,114,64,228,53,77,39,189,135,116,28,59,109,221,
			22,125,89,52,190,236,207,33,94,208,66,35,169,188,195,251,136,39,173,50,21,245,166,2,85,253,165,148,154,92,154,126,
		],
		[
			0,243,77,17,232,182,118,124,226,162,179,192,213,8,128,31,249,116,129,190,14,129,189,196,101,9,81,167,252,88,53,231,
			7,59,212,86,35,230,209,193,250,219,174,29,205,110,68,52,71,166,82,183,215,80,173,93,128,75,154,159,79,216,135,145,
		],
	]
};

/**
 * Calculates the expected public amount from ext_amount and fee, then verifies if it matches
 * the provided public_amount_bytes.
 *
 * @param ext_amount The external amount (can be positive or negative), as i64.
 * @param fee The fee (non-negative), as u64.
 * @param public_amount_bytes The public amount to verify against, as a 32-byte array (big-endian).
 * @return Returns `true` if the calculated public amount matches public_amount_bytes AND 
 *         the input ext_amount and fee are valid according to predefined limits. 
 *         Returns `false` otherwise (either due to mismatch or invalid inputs for calculation).
 */
pub fn check_public_amount(ext_amount: i64, fee: u64, public_amount_bytes: [u8; 32]) -> bool {
    if ext_amount == i64::MIN {
        msg!("can't use i64::MIN as ext_amount"); 
        return false;
    }

    // Convert to field elements for proper BN254 arithmetic
    let fee_fr = Fr::from(fee);
    let ext_amount_fr = if ext_amount >= 0 {
        Fr::from(ext_amount as u64)
    } else {
        let abs_ext_amount = match ext_amount.checked_neg() {
            Some(val) => val,
            None => return false,
        };
        Fr::from(abs_ext_amount as u64)
    };

    // return false if the deposit amount is barely enough to cover the fee
    if ext_amount >= 0 && ext_amount_fr <= fee_fr {
        return false;
    }

    let result_public_amount = if ext_amount >= 0 {
        // For positive amounts: public_amount = ext_amount - fee
        ext_amount_fr - fee_fr
    } else {
        // For negative amounts: public_amount = -abs(ext_amount) - fee
        // In field arithmetic, this becomes: FIELD_SIZE - (abs(ext_amount) + fee)
        -(ext_amount_fr + fee_fr)
    };

    // Convert provided bytes to field element for comparison
    let provided_amount = Fr::from_be_bytes_mod_order(&public_amount_bytes);
    
    result_public_amount == provided_amount
}

/**
 * Validates that the provided fee meets the minimum required fee based on global configuration.
 * 
 * For deposits (ext_amount > 0):
 * - expected_fee = (ext_amount * deposit_fee_rate) / 10000
 * - minimum_fee = expected_fee * (1 - fee_error_margin/10000)
 * 
 * For withdrawals (ext_amount < 0):
 * - expected_fee = (abs(ext_amount) * withdrawal_fee_rate) / 10000
 * - minimum_fee = expected_fee * (1 - fee_error_margin/10000)
 * 
 * @param ext_amount The external amount (positive for deposits, negative for withdrawals)
 * @param provided_fee The fee provided by the user
 * @param deposit_fee_rate Fee rate for deposits (in basis points, 0-10000)
 * @param withdrawal_fee_rate Fee rate for withdrawals (in basis points, 0-10000)
 * @param fee_error_margin Tolerance rate (in basis points, 0-10000)
 * @return Ok(()) if fee is valid, Err(ErrorCode) if invalid
 */
pub fn validate_fee(
    ext_amount: i64,
    provided_fee: u64,
    deposit_fee_rate: u16,
    withdrawal_fee_rate: u16,
    fee_error_margin: u16,
) -> Result<()> {
    if ext_amount > 0 {
        // Deposit: check fee against deposit rate
        let expected_fee = (ext_amount as u128)
            .checked_mul(deposit_fee_rate as u128)
            .ok_or(ErrorCode::ArithmeticOverflow)?
            .checked_div(10000)
            .ok_or(ErrorCode::ArithmeticOverflow)? as u64;
        
        // Calculate minimum acceptable fee: expected_fee * (1 - fee_error_margin/10000)
        let min_acceptable_fee = if expected_fee > 0 {
            let error_multiplier = 10000u128.checked_sub(fee_error_margin as u128)
                .ok_or(ErrorCode::ArithmeticOverflow)?;
            (expected_fee as u128)
                .checked_mul(error_multiplier)
                .ok_or(ErrorCode::ArithmeticOverflow)?
                .checked_div(10000)
                .ok_or(ErrorCode::ArithmeticOverflow)? as u64
        } else {
            0 // If expected fee is 0, minimum is also 0
        };
        
        require!(
            provided_fee >= min_acceptable_fee,
            ErrorCode::InvalidFeeAmount
        );
    } else if ext_amount < 0 {
        // Withdrawal: check fee against withdrawal rate
        let withdrawal_amount = ext_amount.checked_neg()
            .ok_or(ErrorCode::ArithmeticOverflow)? as u64;
        
        let expected_fee = (withdrawal_amount as u128)
            .checked_mul(withdrawal_fee_rate as u128)
            .ok_or(ErrorCode::ArithmeticOverflow)?
            .checked_div(10000)
            .ok_or(ErrorCode::ArithmeticOverflow)? as u64;
        
        // Calculate minimum acceptable fee: expected_fee * (1 - fee_error_margin/10000)
        let min_acceptable_fee = if expected_fee > 0 {
            let error_multiplier = 10000u128.checked_sub(fee_error_margin as u128)
                .ok_or(ErrorCode::ArithmeticOverflow)?;
            (expected_fee as u128)
                .checked_mul(error_multiplier)
                .ok_or(ErrorCode::ArithmeticOverflow)?
                .checked_div(10000)
                .ok_or(ErrorCode::ArithmeticOverflow)? as u64
        } else {
            0 // If expected fee is 0, minimum is also 0
        };
        
        require!(
            provided_fee >= min_acceptable_fee,
            ErrorCode::InvalidFeeAmount
        );
    }
    // For ext_amount == 0, no fee validation needed
    
    Ok(())
}


pub fn verify_compressed_proof(proof: CompressedProof, verifying_key: Groth16Verifyingkey, mint_address_a: Pubkey, mint_address_b: Pubkey) -> bool {
    let mut public_inputs_vec: [[u8; 32]; 10] = [[0u8; 32]; 10];
    public_inputs_vec[0] = proof.root;
    public_inputs_vec[1] = proof.public_amount0;
    public_inputs_vec[2] = proof.public_amount1;
    public_inputs_vec[3] = proof.ext_data_hash;
    public_inputs_vec[4] = mint_address_a.to_bytes();
    public_inputs_vec[5] = mint_address_b.to_bytes();
    public_inputs_vec[6] = proof.input_nullifiers[0];
    public_inputs_vec[7] = proof.input_nullifiers[1];
    public_inputs_vec[8] = proof.output_commitments[0];
    public_inputs_vec[9] = proof.output_commitments[1];
    msg!("decompressing proof_a");
    let proof_a = decompress_g1(&proof.proof_a).map_err(|e| {
        let code: u32 = e.into();
        Error::from(ProgramError::Custom(code))
    }).unwrap();

    let proof_b = decompress_g2(&proof.proof_b).map_err(|e| {
        let code: u32 = e.into();
        Error::from(ProgramError::Custom(code))
    }).unwrap();
    let proof_c = decompress_g1(&proof.proof_c).map_err(|e| {
        let code: u32 = e.into();
        Error::from(ProgramError::Custom(code))
    }).unwrap();

    msg!("verifying proof");
    let mut verifier = match Groth16Verifier::new(
        &proof_a,
        &proof_b,
        &proof_c,
        &public_inputs_vec,
        &verifying_key
    ) {
        Ok(v) => v,
        Err(_) => return false,
    };

    // Use verify_unchecked because mint addresses (32 bytes) can be larger than BN254 field size
    // Circom and alt_bn128_multiplication automatically handle modulo operation for field elements
    verifier.verify_unchecked().unwrap_or(false)
}


/**
 * Calculate ExtData hash with encrypted outputs included
 * This matches the client-side calculation for hash verification
 */
pub fn calculate_complete_ext_data_hash(
    recipient: Pubkey,
    ext_amount: i64,
    encrypted_output: &[u8],
    fee: u64,
    fee_recipient: Pubkey,
    mint_address_a: Pubkey,
    mint_address_b: Pubkey,
) -> Result<[u8; 32]> {
    #[derive(AnchorSerialize)]
    struct CompleteExtData {
        pub recipient: Pubkey,
        pub ext_amount: i64,
        pub encrypted_output: Vec<u8>,
        pub fee: u64,
        pub fee_recipient: Pubkey,
        pub mint_address_a: Pubkey,
        pub mint_address_b: Pubkey,
    }

    let complete_ext_data = CompleteExtData {
        recipient,
        ext_amount,
        encrypted_output: encrypted_output.to_vec(),
        fee,
        fee_recipient,
        mint_address_a,
        mint_address_b,
    };
    
    let mut serialized_ext_data = Vec::new();
    complete_ext_data.serialize(&mut serialized_ext_data)?;
    let calculated_ext_data_hash = hash(&serialized_ext_data).to_bytes();
    
    Ok(calculated_ext_data_hash)
}

/**
 * Calculate Swap ExtData hash with encrypted outputs and extMinAmountOut included
 * This matches the client-side calculation for hash verification
 */
pub fn calculate_swap_ext_data_hash(
    ext_amount: i64,
    ext_min_amount_out: i64,
    encrypted_output: &[u8],
    fee: u64,
    fee_recipient: Pubkey,
    mint_address_a: Pubkey,
    mint_address_b: Pubkey,
) -> Result<[u8; 32]> {
    #[derive(AnchorSerialize)]
    struct CompleteSwapExtData {
        pub ext_amount: i64,
        pub ext_min_amount_out: i64,
        pub encrypted_output: Vec<u8>,
        pub fee: u64,
        pub fee_recipient: Pubkey,
        pub mint_address_a: Pubkey,
        pub mint_address_b: Pubkey,
    }

    let complete_swap_ext_data = CompleteSwapExtData {
        ext_amount,
        ext_min_amount_out,
        encrypted_output: encrypted_output.to_vec(),
        fee,
        fee_recipient,
        mint_address_a,
        mint_address_b,
    };
    
    let mut serialized_ext_data = Vec::new();
    complete_swap_ext_data.serialize(&mut serialized_ext_data)?;
    let calculated_ext_data_hash = hash(&serialized_ext_data).to_bytes();
    
    Ok(calculated_ext_data_hash)
}

