import * as anchor from "@coral-xyz/anchor";
import { PublicKey } from "@solana/web3.js";

/**
 * Find nullifier PDAs for the given proof
 * @param program - Anchor program instance
 * @param proof - Proof object containing input nullifiers
 * @returns Object containing nullifier0PDA and nullifier1PDA
 */
export function findNullifierPDAs(program: anchor.Program<any>, proof: any) {
  const [nullifier0PDA] = PublicKey.findProgramAddressSync(
    [Buffer.from("nullifier"), Buffer.from(proof.inputNullifiers[0])],
    program.programId
  );
  
  const [nullifier1PDA] = PublicKey.findProgramAddressSync(
    [Buffer.from("nullifier"), Buffer.from(proof.inputNullifiers[1])],
    program.programId
  );
  
  return { nullifier0PDA, nullifier1PDA };
}

/**
 * Find commitment PDAs for the given proof
 * @param program - Anchor program instance
 * @param proof - Proof object containing output commitments
 * @returns Object containing commitment0PDA and commitment1PDA
 */
export function findCommitmentPDAs(program: anchor.Program<any>, proof: any) {
  const [commitment0PDA] = PublicKey.findProgramAddressSync(
    [Buffer.from("commitment0"), Buffer.from(proof.outputCommitments[0])],
    program.programId
  );
  
  const [commitment1PDA] = PublicKey.findProgramAddressSync(
    [Buffer.from("commitment1"), Buffer.from(proof.outputCommitments[1])],
    program.programId
  );
  
  return { commitment0PDA, commitment1PDA };
}



/**
 * Find the merkle tree PDA
 * @param programId - Program ID
 * @returns Merkle tree PDA and bump
 */
export function findMerkleTreePDA(programId: PublicKey) {
  return PublicKey.findProgramAddressSync(
    [Buffer.from("merkle_tree")],
    programId
  );
}

/**
 * Find the tree token account PDA
 * @param programId - Program ID
 * @returns Tree token account PDA and bump
 */
export function findTreeTokenAccountPDA(programId: PublicKey) {
  return PublicKey.findProgramAddressSync(
    [Buffer.from("tree_token")],
    programId
  );
}

/**
 * Find the global config PDA
 * @param programId - Program ID
 * @returns Global config PDA and bump
 */
export function findGlobalConfigPDA(programId: PublicKey) {
  return PublicKey.findProgramAddressSync(
    [Buffer.from("global_config")],
    programId
  );
}

