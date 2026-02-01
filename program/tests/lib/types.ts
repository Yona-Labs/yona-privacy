import { PublicKey } from "@solana/web3.js";
import { BN } from "@coral-xyz/anchor";

/**
 * External data structure for deposit/transact operations
 */
export interface ExtData {
  recipient: PublicKey;
  extAmount: BN;
  encryptedOutput: Buffer;
  fee: BN;
  feeRecipient: PublicKey;
  mintAddressA: PublicKey;
  mintAddressB: PublicKey;
}

export interface SwapData {
  extAmount: BN;
  extMinAmountOut: BN;
  encryptedOutput: Buffer;
  fee: BN;
  feeRecipient: PublicKey;
  mintAddressA: PublicKey;
  mintAddressB: PublicKey;
}


/**
 * Proof structure ready to submit to the program
 */
export interface ProofToSubmit {
  proofA: number[];
  proofB: number[];
  proofC: number[];
  root: number[];
  publicAmount0: number[];
  publicAmount1: number[];
  extDataHash: number[];
  inputNullifiers: number[][];
  outputCommitments: number[][];
}


/**
 * Input structure for the zero-knowledge proof generation
 */
export interface ProofInput {
  root: string;
  inputNullifier: string[];
  outputCommitment: string[];
  publicAmount0: string;
  publicAmount1: string;
  extDataHash: Uint8Array;
  mintAddress0: string;
  mintAddress1: string;
  inAmount: string[];
  inMintAddress: string[];
  inPrivateKey: (string | BN)[];
  inBlinding: string[];
  inPathIndices: number[];
  inPathElements: string[][];
  outAmount: string[];
  outMintAddress: string[];
  outPubkey: (string | BN)[];
  outBlinding: string[];
}
/**
 * Parsed proof structure with separate components
 */
export interface ParsedProof {
  proofA: number[];
  proofB: number[][];
  proofC: number[];
}

