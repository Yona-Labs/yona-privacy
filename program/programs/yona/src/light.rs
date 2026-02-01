use anchor_lang::prelude::*;
use light_sdk::{
    account::LightAccount,
    address::v1::derive_address,
    cpi::{
        v1::{CpiAccounts, LightSystemProgramCpi},
        CpiSigner, InvokeLightSystemProgram, LightCpiInstruction,
    },
    derive_light_cpi_signer,
    instruction::{PackedAddressTreeInfo, ValidityProof},
    LightDiscriminator,
};
use crate::ErrorCode;

// Canonical address tree pubkey - all nullifiers must be derived from this tree
// This ensures a single address space: same nullifier hash = same PDA across the protocol
pub const CANONICAL_ADDRESS_TREE: Pubkey = pubkey!("amt1Ayt45jfbdw5YSo7iz6WZxUmnZsQTYXy82hVwyC2");

// Light Protocol CPI signer for this program
pub const LIGHT_CPI_SIGNER: CpiSigner =
    derive_light_cpi_signer!("yonaMBw7KLYvQSspboB2GGAt5EsQqV28dZZasKhKGqC");

// Nullifier compressed account structure - just marks the nullifier as used
#[derive(Clone, Debug, Default, LightDiscriminator, AnchorSerialize, AnchorDeserialize)]
pub struct NullifierCompressedAccount {
    // The nullifier hash that this account represents
    pub nullifier: [u8; 32],
}

/// Creates Light Protocol nullifier compressed accounts for both input nullifiers
/// This prevents double-spending by creating unique addresses for each nullifier
/// 
/// # Arguments
/// * `payer` - The account that pays for the transaction
/// * `remaining_accounts` - Remaining accounts containing Light Protocol state trees
/// * `input_nullifiers` - Array of two nullifier hashes from the ZK proof
/// * `light_proof` - Light Protocol validity proof
/// * `nullifier0_address_tree_info` - Packed address tree info for first nullifier
/// * `nullifier1_address_tree_info` - Packed address tree info for second nullifier
/// * `output_state_tree_index` - Index of the output state tree
pub fn create_light_nullifiers<'info>(
    payer: &AccountInfo<'info>,
    remaining_accounts: &[AccountInfo<'info>],
    input_nullifiers: &[[u8; 32]; 2],
    light_proof: ValidityProof,
    nullifier0_address_tree_info: PackedAddressTreeInfo,
    nullifier1_address_tree_info: PackedAddressTreeInfo,
    output_state_tree_index: u8,
) -> Result<()> {
    
    let light_cpi_accounts = CpiAccounts::new(
        payer,
        remaining_accounts,
        LIGHT_CPI_SIGNER,
    );

    // Get and validate address tree pubkey for nullifier 0
    let nullifier0_tree_pubkey = nullifier0_address_tree_info
        .get_tree_pubkey(&light_cpi_accounts)
        .map_err(|_| ErrorCode::InvalidNullifierAddress)?;
    
    // Validate address tree is the canonical one (same tree = same address space)
    require!(
        nullifier0_tree_pubkey == CANONICAL_ADDRESS_TREE,
        ErrorCode::InvalidAddressTree
    );

    // Get and validate address tree pubkey for nullifier 1
    let nullifier1_tree_pubkey = nullifier1_address_tree_info
        .get_tree_pubkey(&light_cpi_accounts)
        .map_err(|_| ErrorCode::InvalidNullifierAddress)?;
    
    // Validate address tree is the canonical one
    require!(
        nullifier1_tree_pubkey == CANONICAL_ADDRESS_TREE,
        ErrorCode::InvalidAddressTree
    );

    // Derive address for nullifier 0
    let (nullifier0_address, nullifier0_seed) = derive_address(
        &[b"nullifier", input_nullifiers[0].as_ref()],
        &nullifier0_tree_pubkey,
        &crate::ID,
    );

    // Derive address for nullifier 1
    let (nullifier1_address, nullifier1_seed) = derive_address(
        &[b"nullifier", input_nullifiers[1].as_ref()],
        &nullifier1_tree_pubkey,
        &crate::ID,
    );

    // Create compressed account for nullifier 0
    let mut nullifier0_account = LightAccount::<NullifierCompressedAccount>::new_init(
        &crate::ID,
        Some(nullifier0_address),
        output_state_tree_index,
    );
    nullifier0_account.nullifier = input_nullifiers[0];

    // Create compressed account for nullifier 1
    let mut nullifier1_account = LightAccount::<NullifierCompressedAccount>::new_init(
        &crate::ID,
        Some(nullifier1_address),
        output_state_tree_index,
    );
    nullifier1_account.nullifier = input_nullifiers[1];

    // CPI to Light System Program to create both nullifier compressed accounts
    // If these addresses already exist, the proof verification will fail
    let new_address_params0 = nullifier0_address_tree_info.into_new_address_params_packed(nullifier0_seed);
    let new_address_params1 = nullifier1_address_tree_info.into_new_address_params_packed(nullifier1_seed);

    LightSystemProgramCpi::new_cpi(LIGHT_CPI_SIGNER, light_proof)
        .with_light_account(nullifier0_account)
        .map_err(|_| ErrorCode::LightProtocolError)?
        .with_light_account(nullifier1_account)
        .map_err(|_| ErrorCode::LightProtocolError)?
        .with_new_addresses(&[new_address_params0, new_address_params1])
        .invoke(light_cpi_accounts)
        .map_err(|_| ErrorCode::LightProtocolError)?;

    
    Ok(())
}


