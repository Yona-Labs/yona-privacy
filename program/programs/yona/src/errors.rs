use thiserror::Error;
use anchor_lang::prelude::*;

#[derive(Error, Debug, PartialEq, Eq)]
pub enum Groth16Error {
    #[error("Invalid G1 point length")]
    InvalidG1Length,
    
    #[error("Invalid G2 point length")]
    InvalidG2Length,
    
    #[error("Invalid public inputs length")]
    InvalidPublicInputsLength,
    
    #[error("Public input greater than field size")]
    PublicInputGreaterThanFieldSize,
    
    #[error("Preparing inputs G1 multiplication failed")]
    PreparingInputsG1MulFailed,
    
    #[error("Preparing inputs G1 addition failed")]
    PreparingInputsG1AdditionFailed,
    
    #[error("Proof verification failed")]
    ProofVerificationFailed,
}

#[error_code]
pub enum ErrorCode {
    #[msg("Not authorized to perform this action")]
    Unauthorized,
    #[msg("External data hash does not match the one in the proof")]
    ExtDataHashMismatch,
    #[msg("Root is not known in the tree")]
    UnknownRoot,
    #[msg("Public amount is invalid")]
    InvalidPublicAmountData,
    #[msg("Insufficient funds for withdrawal")]
    InsufficientFundsForWithdrawal,
    #[msg("Insufficient funds for fee")]
    InsufficientFundsForFee,
    #[msg("Proof is invalid")]
    InvalidProof,
    #[msg("Invalid fee: fee must be less than MAX_ALLOWED_VAL (2^248).")]
    InvalidFee,
    #[msg("Invalid ext amount: absolute ext_amount must be less than MAX_ALLOWED_VAL (2^248).")]
    InvalidExtAmount,
    #[msg("Public amount calculation resulted in an overflow/underflow.")]
    PublicAmountCalculationError,
    #[msg("Arithmetic overflow/underflow occurred")]
    ArithmeticOverflow,
    #[msg("Deposit limit exceeded")]
    DepositLimitExceeded,
    #[msg("Invalid fee rate: must be between 0 and 10000 basis points")]
    InvalidFeeRate,
    #[msg("Fee recipient does not match global configuration")]
    InvalidFeeRecipient,
    #[msg("Fee amount is below minimum required (must be at least (1 - fee_error_margin) * expected_fee)")]
    InvalidFeeAmount,
    #[msg("Recipient account does not match the ExtData recipient")]
    RecipientMismatch,
    #[msg("Merkle tree is full: cannot add more leaves")]
    MerkleTreeFull,
    #[msg("Unsupported mint address")]
    UnsupportedMintAddress,
    #[msg("Dual-token transactions are not yet supported")]
    DualTokenNotSupported,
    #[msg("Invalid Jupiter swap data")]
    InvalidJupiterSwapData,
    #[msg("Math overflow or underflow occurred")]
    MathOverflow,
    #[msg("Insufficient swap output: received amount is less than minimum required")]
    InsufficientSwapOutput,
    #[msg("Invalid nullifier address derivation")]
    InvalidNullifierAddress,
    #[msg("Light Protocol CPI error")]
    LightProtocolError,
    #[msg("Invalid address tree: must use the canonical address tree")]
    InvalidAddressTree,
} 