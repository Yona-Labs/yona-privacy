import * as anchor from "@coral-xyz/anchor";
import { createAssociatedTokenAccountInstruction, getAssociatedTokenAddressSync, TOKEN_PROGRAM_ID, createTransferInstruction } from "@solana/spl-token";
import { ComputeBudgetProgram, Keypair, LAMPORTS_PER_SOL, PublicKey, Transaction, TransactionInstruction, AccountMeta } from "@solana/web3.js";
import { Yona } from "../target/types/yona";
import {
  findNullifierPDAs,
  findMerkleTreePDA,
  findTreeTokenAccountPDA,
  findGlobalConfigPDA
} from "./lib/derive";
import { BanksClient, ProgramTestContext } from "solana-bankrun";
import { createMint } from "./lib/token";
import { ExtData, SwapData } from "./lib/types";
import {
  bn,
  defaultStaticAccountsStruct,
  defaultTestStateTreeAccounts,
  deriveAddress,
  deriveAddressSeed,
  TreeInfo,
  Rpc,
  toAccountMetas,
  packNewAddressParams,
  LightSystemProgram,
} from "@lightprotocol/stateless.js";
import { PackedAccounts, SystemAccountMetaConfig } from "./lib/light-helpers";

/**
 * Proof structure for ZK verification
 */
export interface Proof {
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
 * Minified external data structure (for on-chain)
 */
export interface ExtDataMinified {
  extAmount: anchor.BN;
  fee: anchor.BN;
}

/**
 * Minified swap external data structure (for on-chain)
 */
export interface SwapExtDataMinified {
  extAmount: anchor.BN;
  extMinAmountOut: anchor.BN;
  fee: anchor.BN;
}

/**
 * Helper function to create ExtDataMinified from ExtData
 * @param extData - Full ExtData object
 * @returns Minified ExtData with only extAmount and fee
 */
export function createExtDataMinified(extData: ExtData): ExtDataMinified {
  return {
    extAmount: extData.extAmount,
    fee: extData.fee
  };
}

/**
 * Helper function to create SwapExtDataMinified from SwapData
 * @param swapData - Full SwapData object
 * @returns Minified SwapData with extAmount, extMinAmountOut, fee, and feeRecipient
 */
export function createSwapExtDataMinified(swapData: SwapData): SwapExtDataMinified {
  return {
    extAmount: swapData.extAmount,
    extMinAmountOut: swapData.extMinAmountOut,
    fee: swapData.fee,
  };
}

/**
 * Build transact instruction (DEPRECATED - use buildDepositWithLightNullifiersInstruction instead)
 * This function is deprecated as deposit now requires Light Protocol nullifiers.
 * Kept for reference only.
 */
export async function buildDepositInstruction(
  program: anchor.Program<Yona>,
  proof: Proof,
  extData: ExtData,
  signer: PublicKey,
  inputMint: PublicKey
): Promise<TransactionInstruction[]> {
  throw new Error("buildDepositInstruction is deprecated. Use buildDepositWithLightNullifiersInstruction instead.");
}

/**
 * Light Protocol packed address tree info structure
 */
export interface PackedAddressTreeInfo {
  rootIndex: number;
  addressMerkleTreePubkeyIndex: number;
  addressQueuePubkeyIndex: number;
}


/**
 * Build deposit instruction with Light Protocol nullifiers
 * @param program - Anchor program instance
 * @param proof - ZK proof data
 * @param extData - External data (recipient, amount, fee, etc.)
 * @param signer - Transaction signer public key
 * @param inputMint - Token mint address
 * @param lightRpc - Light Protocol RPC client
 * @returns Transaction instruction
 */
export async function buildDepositWithLightNullifiersInstruction(
  program: anchor.Program<Yona>,
  proof: Proof,
  extData: ExtData,
  signer: PublicKey,
  inputMint: PublicKey,
  lightRpc: Rpc
): Promise<TransactionInstruction[]> {
  // Derive all necessary PDAs
  const [treeAccount] = findMerkleTreePDA(program.programId);
  const [globalConfig] = findGlobalConfigPDA(program.programId);

  // Derive reserve token accounts
  const reserveTokenAccount = getAssociatedTokenAddressSync(
    inputMint,
    globalConfig,
    true
  );
  const userTokenAccount = getAssociatedTokenAddressSync(
    inputMint,
    signer,
    true
  );

  // Get Light Protocol state tree accounts
  const { merkleTree: outputStateTree, addressTree, addressQueue } = defaultTestStateTreeAccounts();
  // Derive nullifier addresses using Light Protocol
  const nullifier0Seed = deriveAddressSeed(
    [Buffer.from("nullifier"), Buffer.from(proof.inputNullifiers[0])],
    program.programId,
  );
  const nullifier0Address = deriveAddress(nullifier0Seed, addressTree);

  const nullifier1Seed = deriveAddressSeed(
    [Buffer.from("nullifier"), Buffer.from(proof.inputNullifiers[1])],
    program.programId,
  );
  const nullifier1Address = deriveAddress(nullifier1Seed, addressTree);

  console.log("Nullifier 0 address:", nullifier0Address.toBase58());
  console.log("Nullifier 1 address:", nullifier1Address.toBase58());

  // Get validity proof for the two new addresses (proves they don't exist yet)
  const proofResult = await lightRpc.getValidityProofV0(
    [], // No existing hashes to prove
    [
      {
        tree: addressTree,
        queue: addressQueue,
        address: bn(nullifier0Address.toBytes()),
      },
      {
        tree: addressTree,
        queue: addressQueue,
        address: bn(nullifier1Address.toBytes()),
      },
    ],
  );

  console.log("Got Light Protocol validity proof");
  console.log("Root indices:", proofResult.rootIndices);

  // Use PackedAccounts API to build remaining accounts correctly
  const systemAccountConfig = SystemAccountMetaConfig.new(program.programId);
  const packedAccounts = PackedAccounts.newWithSystemAccounts(systemAccountConfig);

  // Insert tree accounts and get their indices
  const addressMerkleTreePubkeyIndex = packedAccounts.insertOrGet(addressTree);
  const addressQueuePubkeyIndex = packedAccounts.insertOrGet(addressQueue);
  const outputMerkleTreeIndex = packedAccounts.insertOrGet(outputStateTree);
  
  // Add nullifier queue
  const nullifierQueue = defaultTestStateTreeAccounts().nullifierQueue;
  packedAccounts.insertOrGet(nullifierQueue);

  console.log("addressMerkleTreePubkeyIndex: ", addressMerkleTreePubkeyIndex);
  console.log("addressQueuePubkeyIndex: ", addressQueuePubkeyIndex);
  console.log("outputMerkleTreeIndex: ", outputMerkleTreeIndex);
  console.log("nullifier0Address: ", nullifier0Address);
  console.log("nullifier1Address: ", nullifier1Address);

  // Pack address tree info for nullifier 0
  const nullifier0AddressTreeInfo: PackedAddressTreeInfo = {
    rootIndex: proofResult.rootIndices[0],
    addressMerkleTreePubkeyIndex,
    addressQueuePubkeyIndex,
  };

  // Pack address tree info for nullifier 1
  const nullifier1AddressTreeInfo: PackedAddressTreeInfo = {
    rootIndex: proofResult.rootIndices[1] ?? proofResult.rootIndices[0],
    addressMerkleTreePubkeyIndex,
    addressQueuePubkeyIndex,
  };

  // Output state tree index from PackedAccounts
  const outputStateTreeIndex = outputMerkleTreeIndex;

  // Light validity proof - Anchor expects it wrapped in { 0: ... } format
  const lightProof = {
    0: {
      a: Array.from(proofResult.compressedProof.a),
      b: Array.from(proofResult.compressedProof.b),
      c: Array.from(proofResult.compressedProof.c),
    }
  };

  const ixs = [];
  console.log("packedAccounts", (packedAccounts.toAccountMetas().remainingAccounts.length))
  // Build instruction with Light Protocol parameters
  const instruction = await program.methods
    .deposit(
      proof,
      createExtDataMinified(extData),
      extData.encryptedOutput,
      lightProof,
      nullifier0AddressTreeInfo,
      nullifier1AddressTreeInfo,
      outputStateTreeIndex
    )
    .accountsStrict({
      treeAccount,
      globalConfig,
      inputMint: inputMint,
      reserveTokenAccount: reserveTokenAccount,
      feeRecipientAccount: extData.feeRecipient,
      userTokenAccount: userTokenAccount,
      user: signer,
      systemProgram: anchor.web3.SystemProgram.programId,
      tokenProgram: TOKEN_PROGRAM_ID
    })
    .remainingAccounts(packedAccounts.toAccountMetas().remainingAccounts)
    .instruction();

  ixs.push(instruction);

  return ixs;
}

/**
 * Build withdraw instruction (DEPRECATED - use buildWithdrawWithLightNullifiersInstruction instead)
 * This function is deprecated as withdraw now requires Light Protocol nullifiers.
 * Kept for reference only.
 */
export async function buildWithdrawInstruction(
  program: anchor.Program<Yona>,
  proof: Proof,
  extData: ExtData,
  signer: PublicKey,
  inputMint: PublicKey
): Promise<TransactionInstruction[]> {
  throw new Error("buildWithdrawInstruction is deprecated. Use buildWithdrawWithLightNullifiersInstruction instead.");
}

/**
 * Build withdraw instruction with Light Protocol nullifiers
 * @param program - Anchor program instance
 * @param proof - ZK proof data
 * @param extData - External data (recipient, amount, fee, etc.)
 * @param signer - Transaction signer public key (relayer)
 * @param inputMint - Token mint address
 * @param lightRpc - Light Protocol RPC client
 * @returns Transaction instruction
 */
export async function buildWithdrawWithLightNullifiersInstruction(
  program: anchor.Program<Yona>,
  proof: Proof,
  extData: ExtData,
  signer: PublicKey,
  inputMint: PublicKey,
  lightRpc: Rpc
): Promise<TransactionInstruction[]> {
  // Derive all necessary PDAs
  const [treeAccount] = findMerkleTreePDA(program.programId);
  const [globalConfig] = findGlobalConfigPDA(program.programId);

  // Derive reserve token account
  const reserveTokenAccount = getAssociatedTokenAddressSync(
    inputMint,
    globalConfig,
    true
  );

  // Derive recipient token account
  const recipientTokenAccount = getAssociatedTokenAddressSync(
    inputMint,
    extData.recipient,
    true
  );

  // Get Light Protocol state tree accounts
  const { merkleTree: outputStateTree, addressTree, addressQueue } = defaultTestStateTreeAccounts();
  
  // Derive nullifier addresses using Light Protocol
  const nullifier0Seed = deriveAddressSeed(
    [Buffer.from("nullifier"), Buffer.from(proof.inputNullifiers[0])],
    program.programId,
  );
  const nullifier0Address = deriveAddress(nullifier0Seed, addressTree);

  const nullifier1Seed = deriveAddressSeed(
    [Buffer.from("nullifier"), Buffer.from(proof.inputNullifiers[1])],
    program.programId,
  );
  const nullifier1Address = deriveAddress(nullifier1Seed, addressTree);

  console.log("Withdraw - Nullifier 0 address:", nullifier0Address.toBase58());
  console.log("Withdraw - Nullifier 1 address:", nullifier1Address.toBase58());

  // Get validity proof for the two new addresses (proves they don't exist yet)
  const proofResult = await lightRpc.getValidityProofV0(
    [], // No existing hashes to prove
    [
      {
        tree: addressTree,
        queue: addressQueue,
        address: bn(nullifier0Address.toBytes()),
      },
      {
        tree: addressTree,
        queue: addressQueue,
        address: bn(nullifier1Address.toBytes()),
      },
    ],
  );

  console.log("Got Light Protocol validity proof for withdraw");
  console.log("Root indices:", proofResult.rootIndices);

  // Use PackedAccounts API to build remaining accounts correctly
  const systemAccountConfig = SystemAccountMetaConfig.new(program.programId);
  const packedAccounts = PackedAccounts.newWithSystemAccounts(systemAccountConfig);

  // Insert tree accounts and get their indices
  const addressMerkleTreePubkeyIndex = packedAccounts.insertOrGet(addressTree);
  const addressQueuePubkeyIndex = packedAccounts.insertOrGet(addressQueue);
  const outputMerkleTreeIndex = packedAccounts.insertOrGet(outputStateTree);
  
  // Add nullifier queue
  const nullifierQueue = defaultTestStateTreeAccounts().nullifierQueue;
  packedAccounts.insertOrGet(nullifierQueue);

  // Pack address tree info for nullifier 0
  const nullifier0AddressTreeInfo: PackedAddressTreeInfo = {
    rootIndex: proofResult.rootIndices[0],
    addressMerkleTreePubkeyIndex,
    addressQueuePubkeyIndex,
  };

  // Pack address tree info for nullifier 1
  const nullifier1AddressTreeInfo: PackedAddressTreeInfo = {
    rootIndex: proofResult.rootIndices[1] ?? proofResult.rootIndices[0],
    addressMerkleTreePubkeyIndex,
    addressQueuePubkeyIndex,
  };

  // Output state tree index from PackedAccounts
  const outputStateTreeIndex = outputMerkleTreeIndex;

  // Light validity proof - Anchor expects it wrapped in { 0: ... } format
  const lightProof = {
    0: {
      a: Array.from(proofResult.compressedProof.a),
      b: Array.from(proofResult.compressedProof.b),
      c: Array.from(proofResult.compressedProof.c),
    }
  };

  const ixs = [];
  console.log("packedAccounts", (packedAccounts.toAccountMetas().remainingAccounts.length))

  // Build instruction with Light Protocol parameters
  const instruction = await program.methods
    .withdraw(
      proof,
      createExtDataMinified(extData),
      extData.encryptedOutput,
      lightProof,
      nullifier0AddressTreeInfo,
      nullifier1AddressTreeInfo,
      outputStateTreeIndex
    )
    .accountsStrict({
      treeAccount,
      globalConfig,
      inputMint: inputMint,
      reserveTokenAccount: reserveTokenAccount,
      recipientTokenAccount: recipientTokenAccount,
      feeRecipientAccount: extData.feeRecipient,
      recipient: extData.recipient,
      relayer: signer,
      systemProgram: anchor.web3.SystemProgram.programId,
      tokenProgram: TOKEN_PROGRAM_ID
    })
    .remainingAccounts(packedAccounts.toAccountMetas().remainingAccounts)
    .instruction();

  ixs.push(instruction);

  return ixs;
}

/**
 * Build swap instruction with Light Protocol nullifiers
 * @param program - Anchor program instance
 * @param proof - ZK proof data
 * @param swapData - Swap data (amounts, fees, etc.)
 * @param signer - Transaction signer public key
 * @param inputMint - Input token mint address
 * @param outputMint - Output token mint address
 * @param lightRpc - Light Protocol RPC client
 * @param jupiterSwapData - Optional Jupiter swap data
 * @param jupiterRemainingAccounts - Optional Jupiter remaining accounts
 * @returns Transaction instruction
 */
export async function buildSwapWithLightNullifiersInstruction(
  program: anchor.Program<Yona>,
  proof: Proof,
  swapData: SwapData,
  signer: PublicKey,
  inputMint: PublicKey,
  outputMint: PublicKey,
  lightRpc: Rpc,
  jupiterSwapData: Buffer = Buffer.from([]),
  jupiterRemainingAccounts: any[] = []
): Promise<TransactionInstruction[]> {
  // Derive all necessary PDAs
  const [treeAccount] = findMerkleTreePDA(program.programId);
  const [globalConfig] = findGlobalConfigPDA(program.programId);

  // Derive reserve token accounts for both mints
  const reserveTokenAccountInput = getAssociatedTokenAddressSync(
    inputMint,
    globalConfig,
    true
  );

  const reserveTokenAccountOutput = getAssociatedTokenAddressSync(
    outputMint,
    globalConfig,
    true
  );

  // Derive fee recipient token account for output mint (fee is taken from output)
  const feeRecipientTokenAccount = getAssociatedTokenAddressSync(
    outputMint,
    swapData.feeRecipient,
    true
  );

  // Get Light Protocol state tree accounts
  const { merkleTree: outputStateTree, addressTree, addressQueue } = defaultTestStateTreeAccounts();
  
  // Derive nullifier addresses using Light Protocol
  const nullifier0Seed = deriveAddressSeed(
    [Buffer.from("nullifier"), Buffer.from(proof.inputNullifiers[0])],
    program.programId,
  );
  const nullifier0Address = deriveAddress(nullifier0Seed, addressTree);

  const nullifier1Seed = deriveAddressSeed(
    [Buffer.from("nullifier"), Buffer.from(proof.inputNullifiers[1])],
    program.programId,
  );
  const nullifier1Address = deriveAddress(nullifier1Seed, addressTree);

  console.log("Swap - Nullifier 0 address:", nullifier0Address.toBase58());
  console.log("Swap - Nullifier 1 address:", nullifier1Address.toBase58());

  // Get validity proof for the two new addresses (proves they don't exist yet)
  const proofResult = await lightRpc.getValidityProofV0(
    [], // No existing hashes to prove
    [
      {
        tree: addressTree,
        queue: addressQueue,
        address: bn(nullifier0Address.toBytes()),
      },
      {
        tree: addressTree,
        queue: addressQueue,
        address: bn(nullifier1Address.toBytes()),
      },
    ],
  );

  console.log("Got Light Protocol validity proof for swap");
  console.log("Root indices:", proofResult.rootIndices);

  // Use PackedAccounts API to build remaining accounts correctly
  const systemAccountConfig = SystemAccountMetaConfig.new(program.programId);
  const packedAccounts = PackedAccounts.newWithSystemAccounts(systemAccountConfig);

  // Insert tree accounts and get their indices
  const addressMerkleTreePubkeyIndex = packedAccounts.insertOrGet(addressTree);
  const addressQueuePubkeyIndex = packedAccounts.insertOrGet(addressQueue);
  const outputMerkleTreeIndex = packedAccounts.insertOrGet(outputStateTree);
  
  // Add nullifier queue
  const nullifierQueue = defaultTestStateTreeAccounts().nullifierQueue;
  packedAccounts.insertOrGet(nullifierQueue);

  // Pack address tree info for nullifier 0
  const nullifier0AddressTreeInfo: PackedAddressTreeInfo = {
    rootIndex: proofResult.rootIndices[0],
    addressMerkleTreePubkeyIndex,
    addressQueuePubkeyIndex,
  };

  // Pack address tree info for nullifier 1
  const nullifier1AddressTreeInfo: PackedAddressTreeInfo = {
    rootIndex: proofResult.rootIndices[1] ?? proofResult.rootIndices[0],
    addressMerkleTreePubkeyIndex,
    addressQueuePubkeyIndex,
  };

  // Output state tree index from PackedAccounts
  const outputStateTreeIndex = outputMerkleTreeIndex;

  // Light validity proof - Anchor expects it wrapped in { 0: ... } format
  const lightProof = {
    0: {
      a: Array.from(proofResult.compressedProof.a),
      b: Array.from(proofResult.compressedProof.b),
      c: Array.from(proofResult.compressedProof.c),
    }
  };

  const ixs = [];

  // Jupiter program ID (required account even when not using Jupiter)
  const jupiterProgramId = new anchor.web3.PublicKey("JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4");

  // Calculate number of Light Protocol accounts in remaining accounts
  const lightRemainingAccounts = packedAccounts.toAccountMetas().remainingAccounts;
  const numLightAccounts = lightRemainingAccounts.length;
  console.log("packedAccounts", (packedAccounts.toAccountMetas().remainingAccounts.length))

  // Build instruction with Light Protocol parameters
  let instructionBuilder = program.methods
    .swap(
      proof,
      createSwapExtDataMinified(swapData),
      swapData.encryptedOutput,
      jupiterSwapData,
      lightProof,
      nullifier0AddressTreeInfo,
      nullifier1AddressTreeInfo,
      outputStateTreeIndex,
    )
    .accountsStrict({
      treeAccount,
      globalConfig,
      inputMint: inputMint,
      outputMint: outputMint,
      reserveTokenAccountInput: reserveTokenAccountInput,
      reserveTokenAccountOutput: reserveTokenAccountOutput,
      feeRecipientAccount: feeRecipientTokenAccount,
      jupiterProgram: jupiterProgramId,
      user: signer,
      systemProgram: anchor.web3.SystemProgram.programId,
      inputTokenProgram: TOKEN_PROGRAM_ID,
      outputTokenProgram: TOKEN_PROGRAM_ID,
    });

  // Combine Light Protocol remaining accounts with Jupiter accounts
  const allRemainingAccounts = [
    ...packedAccounts.toAccountMetas().remainingAccounts,
    ...jupiterRemainingAccounts
  ];

  instructionBuilder = instructionBuilder.remainingAccounts(allRemainingAccounts);

  const instruction = await instructionBuilder.instruction();

  ixs.push(instruction);

  return ixs;
}

/**
 * Build swap instruction (DEPRECATED - use buildSwapWithLightNullifiersInstruction instead)
 * This function is deprecated as swap now requires Light Protocol nullifiers.
 * Kept for reference only.
 */
export async function buildSwapInstruction(
  program: anchor.Program<Yona>,
  proof: Proof,
  swapData: SwapData,
  signer: PublicKey,
  inputMint: PublicKey,
  outputMint: PublicKey,
  jupiterSwapData: Buffer,
  jupiterRemainingAccounts?: any[]
): Promise<TransactionInstruction[]> {
  throw new Error("buildSwapInstruction is deprecated. Use buildSwapWithLightNullifiersInstruction instead.");
}

/**
 * 
 * Execute update deposit limit instruction
 * @param program - Anchor program instance
 * @param newLimit - New deposit limit in lamports
 * @param signers - Array of signers (should include authority)
 * @param preInstructions - Optional pre-instructions
 * @returns Transaction signature
 */
export async function executeUpdateDepositLimit(
  program: anchor.Program<Yona>,
  newLimit: anchor.BN,
  signers: anchor.web3.Keypair[],
  preInstructions?: TransactionInstruction[]
): Promise<string> {
  const [treeAccount] = findMerkleTreePDA(program.programId);

  const txBuilder = program.methods
    .updateDepositLimit(newLimit)
    .accounts({
      treeAccount,
      authority: signers[0].publicKey
    })
    .signers(signers);

  if (preInstructions && preInstructions.length > 0) {
    txBuilder.preInstructions(preInstructions);
  }

  return await txBuilder.rpc();
}

/**
 * Build update global config instruction
 * @param program - Anchor program instance
 * @param authority - Authority public key
 * @param depositFeeRate - Optional new deposit fee rate (in basis points, 0-10000)
 * @param withdrawalFeeRate - Optional new withdrawal fee rate (in basis points, 0-10000)
 * @param feeErrorMargin - Optional new fee error margin (in basis points, 0-10000)
 * @returns Transaction instruction
 */
export async function buildUpdateGlobalConfigInstruction(
  program: anchor.Program<Yona>,
  authority: PublicKey,
  depositFeeRate?: number | null,
  withdrawalFeeRate?: number | null,
  feeErrorMargin?: number | null
) {
  const [globalConfig] = findGlobalConfigPDA(program.programId);

  return await program.methods
    .updateGlobalConfig(
      depositFeeRate ?? null,
      withdrawalFeeRate ?? null,
      feeErrorMargin ?? null
    )
    .accounts({
      globalConfig,
      authority
    })
    .instruction();
}

/**
 * Execute update global config instruction
 * @param program - Anchor program instance
 * @param signers - Array of signers (should include authority)
 * @param depositFeeRate - Optional new deposit fee rate (in basis points, 0-10000)
 * @param withdrawalFeeRate - Optional new withdrawal fee rate (in basis points, 0-10000)
 * @param feeErrorMargin - Optional new fee error margin (in basis points, 0-10000)
 * @param preInstructions - Optional pre-instructions
 * @returns Transaction signature
 */
export async function executeUpdateGlobalConfig(
  program: anchor.Program<Yona>,
  signers: anchor.web3.Keypair[],
  depositFeeRate?: number | null,
  withdrawalFeeRate?: number | null,
  feeErrorMargin?: number | null,
  preInstructions?: TransactionInstruction[]
): Promise<string> {
  const [globalConfig] = findGlobalConfigPDA(program.programId);

  const txBuilder = program.methods
    .updateGlobalConfig(
      depositFeeRate ?? null,
      withdrawalFeeRate ?? null,
      feeErrorMargin ?? null
    )
    .accounts({
      globalConfig,
      authority: signers[0].publicKey
    })
    .signers(signers);

  if (preInstructions && preInstructions.length > 0) {
    txBuilder.preInstructions(preInstructions);
  }

  return await txBuilder.rpc();
}

/**
 * Build initialize instruction
 * @param program - Anchor program instance
 * @param authority - Authority public key
 * @returns Transaction instruction
 */
export async function buildInitializeInstruction(
  program: anchor.Program<Yona>,
  authority: PublicKey
) {
  const [treeAccount] = findMerkleTreePDA(program.programId);
  const [treeTokenAccount] = findTreeTokenAccountPDA(program.programId);
  const [globalConfig] = findGlobalConfigPDA(program.programId);

  return await program.methods
    .initialize()
    .accountsStrict({
      treeAccount,
      treeTokenAccount,
      globalConfig,
      authority,
      systemProgram: anchor.web3.SystemProgram.programId
    })
    .instruction();
}

/**
 * Execute initialize instruction
 * @param program - Anchor program instance
 * @param signers - Array of signers (should include authority)
 * @param preInstructions - Optional pre-instructions
 * @returns Transaction signature
 */
export async function executeInitialize(
  program: anchor.Program<Yona>,
  signers: anchor.web3.Keypair[],
  preInstructions?: TransactionInstruction[]
): Promise<string> {
  const [treeAccount] = findMerkleTreePDA(program.programId);
  const [treeTokenAccount] = findTreeTokenAccountPDA(program.programId);
  const [globalConfig] = findGlobalConfigPDA(program.programId);

  const txBuilder = program.methods
    .initialize()
    .accountsStrict({
      treeAccount,
      treeTokenAccount,
      globalConfig,
      authority: signers[0].publicKey,
      systemProgram: anchor.web3.SystemProgram.programId
    })
    .signers(signers);

  if (preInstructions && preInstructions.length > 0) {
    txBuilder.preInstructions(preInstructions);
  }

  return await txBuilder.rpc();
}





export async function sendBankrunTransaction(
  banksClient: BanksClient,
  instructions: TransactionInstruction | TransactionInstruction[],
  payer: Keypair,
  signers: Keypair[],
  computeUnitLimit?: number,
  lookupTableAddresses?: PublicKey[]
): Promise<Buffer> {


  // Get latest blockhash
  const latestBlockhash = await banksClient.getLatestBlockhash();

  // Prepare instructions array
  const instructionsArray = Array.isArray(instructions) ? instructions : [instructions];

  // Add compute unit limit instruction at the beginning
  const allInstructions = [
    ComputeBudgetProgram.setComputeUnitLimit({ units: computeUnitLimit || 1400000 }),
    ...instructionsArray
  ];

  // If lookup table addresses provided, use versioned transaction
  if (lookupTableAddresses && lookupTableAddresses.length > 0) {
    // Create mock AddressLookupTableAccount for bankrun
    const mockLookupTable = {
      key: PublicKey.default,
      state: {
        addresses: lookupTableAddresses,
        authority: undefined,
        deactivationSlot: BigInt(0),
        lastExtendedSlot: 0,
        lastExtendedSlotStartIndex: 0,
      },
      isActive: () => true,
    };

    // Create the V0 message
    const messageV0 = new anchor.web3.TransactionMessage({
      payerKey: payer.publicKey,
      recentBlockhash: latestBlockhash[0],
      instructions: allInstructions,
    }).compileToV0Message([mockLookupTable]);

    const versionedTx = new anchor.web3.VersionedTransaction(messageV0);

    // Sign transaction
    const allSigners = [payer, ...signers];
    versionedTx.sign(allSigners);

    console.log(`Versioned transaction with ${lookupTableAddresses.length} addresses in LUT`);

    // Process transaction
    await banksClient.processTransaction(versionedTx);

    return Buffer.from(versionedTx.signatures[0]);
  } else {
    // Fallback to legacy transaction
    const tx = new Transaction();

    // Add all instructions
    allInstructions.forEach((ix) => tx.add(ix));

    // Set transaction properties
    tx.recentBlockhash = latestBlockhash[0];
    tx.feePayer = payer.publicKey;

    // Sign transaction
    const allSigners = [payer, ...signers];
    tx.sign(...allSigners);

    console.log(`Legacy transaction`);

    // Process transaction
    await banksClient.processTransaction(tx);

    return tx.signature;
  }
}



/**
 * Send transaction with Address Lookup Table support (for localnet/devnet/mainnet)
 */
export async function sendTransactionWithALT(
  connection: anchor.web3.Connection,
  instructions: TransactionInstruction[],
  payer: Keypair,
  signers: Keypair[],
  altAddress: PublicKey[],
  computeUnitLimit?: number
): Promise<string> {
  // Add compute budget instruction
  const allInstructions = [
    ComputeBudgetProgram.setComputeUnitLimit({ units: computeUnitLimit || 1400000 }),
    ...instructions
  ];

  // Get recent blockhash
  const { blockhash, lastValidBlockHeight } = await connection.getLatestBlockhash();

  let versionedTx: anchor.web3.VersionedTransaction;

  if (altAddress && altAddress.length > 0) {
    // Use versioned transaction with ALT
    const lookupTableAccounts = [];
    for (const alt of altAddress) {
      const lookupTableAccount = await connection.getAddressLookupTable(alt);
      if (!lookupTableAccount.value) {
        throw new Error(`ALT not found: ${alt.toString()}`);  
      }
      lookupTableAccounts.push(lookupTableAccount.value);
    }
    console.log("lookupTableAccounts:", lookupTableAccounts.map(alt => alt.state.addresses.map(addr => addr.toString())));
    const messageV0 = new anchor.web3.TransactionMessage({
      payerKey: payer.publicKey,
      recentBlockhash: blockhash,
      instructions: allInstructions,
    }).compileToV0Message(lookupTableAccounts);

    console.log("Transaction compiled successfully");
    console.log("Message accountKeys length:", messageV0.staticAccountKeys.length);
    console.log("Message addressTableLookups length:", messageV0.addressTableLookups?.length || 0);
    console.log("Message compiledInstructions length:", messageV0.compiledInstructions.length);
    
    // Calculate approximate message size
    let estimatedSize = 0;
    for (const ix of messageV0.compiledInstructions) {
      estimatedSize += ix.data.length;
      console.log("  Instruction data length:", ix.data.length, "bytes");
      console.log("  Instruction accounts:", ix.accountKeyIndexes.length);
    }
    console.log("Total instruction data size:", estimatedSize, "bytes");
    console.log("Static account keys:", messageV0.staticAccountKeys.length);
    
    // Try to serialize to see the actual size
    try {
      const serialized = messageV0.serialize();
      console.log("Serialized message size:", serialized.length, "bytes");
    } catch (e) {
      console.error("Failed to serialize message:", e.message);
      console.log("This usually means the transaction is too large");
      
      // Print detailed info about each instruction
      for (let i = 0; i < allInstructions.length; i++) {
        const ix = allInstructions[i];
        console.log(`Instruction ${i}:`, {
          programId: ix.programId.toBase58(),
          dataLength: ix.data.length,
          keysLength: ix.keys.length
        });
      }
    }
    
    versionedTx = new anchor.web3.VersionedTransaction(messageV0);
  } else {
    // Fallback to V0 without ALT
    const messageV0 = new anchor.web3.TransactionMessage({
      payerKey: payer.publicKey,
      recentBlockhash: blockhash,
      instructions: allInstructions,
    }).compileToV0Message([]);

    versionedTx = new anchor.web3.VersionedTransaction(messageV0);
  }

  // Sign transaction
  const allSigners = [payer, ...signers];
  versionedTx.sign(allSigners);

  // Send and confirm
  const signature = await connection.sendTransaction(versionedTx, {
    skipPreflight: true,
    preflightCommitment: 'confirmed',
  });

  await connection.confirmTransaction({
    signature,
    blockhash,
    lastValidBlockHeight,
  });
    
  return signature;
}


export async function startSetupBankrun(
  program: anchor.Program<Yona>,
  admin: Keypair,
  banksClient: BanksClient,
  context: ProgramTestContext,
  recipient: Keypair,
  feeRecipient: Keypair
) {
  await executeInitialize(program, [admin]);

  const latestBlockhash = context.lastBlockhash;

  // Fund the recipient with SOL for rent exemption using transfer
  const recipientTransferTx = new Transaction();
  recipientTransferTx.recentBlockhash = latestBlockhash;
  recipientTransferTx.feePayer = admin.publicKey;
  recipientTransferTx.add(
    anchor.web3.SystemProgram.transfer({
      fromPubkey: admin.publicKey,
      toPubkey: recipient.publicKey,
      lamports: 0.5 * LAMPORTS_PER_SOL,
    })
  );
  recipientTransferTx.sign(admin);
  await banksClient.processTransaction(recipientTransferTx);

  // Fund the fee recipient with SOL for rent exemption using transfer
  const feeRecipientTransferTx = new Transaction();
  feeRecipientTransferTx.recentBlockhash = latestBlockhash;
  feeRecipientTransferTx.feePayer = admin.publicKey;
  feeRecipientTransferTx.add(
    anchor.web3.SystemProgram.transfer({
      fromPubkey: admin.publicKey,
      toPubkey: feeRecipient.publicKey,
      lamports: 0.5 * LAMPORTS_PER_SOL,
    })
  );
  const [treeTokenAccount] = findTreeTokenAccountPDA(program.programId);
  feeRecipientTransferTx.add(
    anchor.web3.SystemProgram.transfer({
      fromPubkey: admin.publicKey,
      toPubkey: treeTokenAccount,
      lamports: 0.5 * LAMPORTS_PER_SOL,
    })
  );
  feeRecipientTransferTx.sign(admin);
  await banksClient.processTransaction(feeRecipientTransferTx);

  const mintAddressA = await createMint({
    banksClient,
    payer: admin,
    admin,
    lastBlockhash: latestBlockhash,
    decimals: 6,
  });

  const mintAddressB = await createMint({
    banksClient,
    payer: admin,
    admin,
    lastBlockhash: latestBlockhash,
    decimals: 9,
  });
  const [globalConfig] = findGlobalConfigPDA(program.programId);
  // Derive reserve token accounts
  const reserveTokenAccountA = getAssociatedTokenAddressSync(
    mintAddressA,
    globalConfig,
    true
  );
  const reserveTokenAccountB = getAssociatedTokenAddressSync(
    mintAddressB,
    globalConfig,
    true
  );
  const ixs = [];
  ixs.push(
    createAssociatedTokenAccountInstruction(
      admin.publicKey,
      reserveTokenAccountA,
      globalConfig,
      mintAddressA
    )
  );

  // Create reserve token account B if needed
  ixs.push(
    createAssociatedTokenAccountInstruction(
      admin.publicKey,
      reserveTokenAccountB,
      globalConfig,
      mintAddressB
    )
  );
  const tx = new Transaction().add(...ixs);
  tx.recentBlockhash = latestBlockhash;
  tx.feePayer = admin.publicKey;
  tx.sign(admin);
  await banksClient.processTransaction(tx);

  return {
    mintAddressA,
    mintAddressB,
    reserveTokenAccountA,
    reserveTokenAccountB,
  };
}


export async function createAtaBankrun(
  banksClient: BanksClient,
  payer: Keypair,
  recipient: PublicKey,
  mint: PublicKey
) {
  const recipientTokenAccount = getAssociatedTokenAddressSync(
    mint,
    recipient,
    true
  );
  try {
    const accountInfo = await banksClient.getAccount(recipientTokenAccount);
    if (accountInfo) {
      return;
    }
  } catch (error) {
  }
  // Create recipient's ATA if it doesn't exist
  const latestBlockhash = await banksClient.getLatestBlockhash();
  const createAtaTx = new Transaction();
  createAtaTx.recentBlockhash = latestBlockhash[0];
  createAtaTx.feePayer = payer.publicKey;
  createAtaTx.add(
    createAssociatedTokenAccountInstruction(
      payer.publicKey,
      recipientTokenAccount,
      recipient,
      mint
    )
  );
  createAtaTx.sign(payer);
  await banksClient.processTransaction(createAtaTx);
}


export async function transferTokenBankrun(
  banksClient: BanksClient,
  source: Keypair,
  recipient: PublicKey,
  mint: PublicKey,
  amount: number
) {
  const recipientTokenAccount = getAssociatedTokenAddressSync(
    mint,
    recipient,
    true
  );
  const sourceTokenAccount = getAssociatedTokenAddressSync(
    mint,
    source.publicKey,
    true
  );
  const transferTx = new Transaction();
  const latestBlockhash = await banksClient.getLatestBlockhash();

  transferTx.recentBlockhash = latestBlockhash[0];
  transferTx.feePayer = source.publicKey;
  transferTx.add(
    createTransferInstruction(
      sourceTokenAccount,
      recipientTokenAccount,
      source.publicKey,
      amount,

    )
  );
  transferTx.sign(source);
  await banksClient.processTransaction(transferTx);
}