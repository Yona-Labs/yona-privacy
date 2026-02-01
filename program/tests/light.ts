import { setProvider, Program, BN, AnchorProvider, Wallet } from "@coral-xyz/anchor";
import * as anchor from "@coral-xyz/anchor";
import { calculateDepositFee, calculateWithdrawalFee } from "./lib/math";
import { expect } from "chai";
import {
  PublicKey,
  Transaction,
  Keypair,
  Connection,
  clusterApiUrl,
  TransactionInstruction,
  LAMPORTS_PER_SOL,
  SystemProgram,
  sendAndConfirmTransaction,
} from "@solana/web3.js";
import {
  createAssociatedTokenAccountInstruction,
  getAssociatedTokenAddressSync,
  TOKEN_PROGRAM_ID,
  createMint,
  mintTo,
  getOrCreateAssociatedTokenAccount,
  NATIVE_MINT,
} from "@solana/spl-token";
import { Yona } from "../target/types/yona";
import { LightWasm, WasmFactory } from "@lightprotocol/hasher.rs";
import { MerkleTree } from "./lib/merkle_tree";
import { buildDepositInstruction, buildWithdrawInstruction, buildSwapInstruction, sendTransactionWithALT, createSwapExtDataMinified, buildDepositWithLightNullifiersInstruction, buildWithdrawWithLightNullifiersInstruction, buildSwapWithLightNullifiersInstruction } from "./instructions";
import { Utxo } from "./lib/utxo";
import { DEFAULT_HEIGHT, FIELD_SIZE, ROOT_HISTORY_SIZE, ZERO_BYTES, DEPOSIT_FEE_RATE, WITHDRAW_FEE_RATE } from "./lib/constants";
import { getExtDataHash, getSwapExtDataHash, publicKeyToFieldElement } from "./lib/utils";
import { parseProofToBytesArray, parseToBytesArray, prove } from "./lib/prover";
import { findGlobalConfigPDA } from "./lib/derive";
import path from "path";
import { ExtData, ProofToSubmit, ProofInput, SwapData } from "./lib/types";
import { createGlobalTestALT, createNewALT, getTestProtocolAddresses } from "./lib/test_alt";
import { buildSwapWithJupiter } from "./jup";
import {
  bn,
  CompressedAccountWithMerkleContext,
  createRpc,
  Rpc,
  defaultStaticAccountsStruct,
  defaultTestStateTreeAccounts,
  deriveAddress,
  deriveAddressSeed,
  LightSystemProgram,
  sleep,
} from "@lightprotocol/stateless.js";
import { PackedAccounts, SystemAccountMetaConfig } from "./lib/light-helpers";

describe("localnet", () => {
  let provider: AnchorProvider;
  let program: Program<Yona>;
  let connection: Connection;
  let admin: Keypair;
  let recipient: Keypair;
  let feeRecipient: Keypair;
  let lightWasm: LightWasm;
  let globalMerkleTree: MerkleTree;
  let mintAddressA: PublicKey;
  let mintAddressB: PublicKey;
  let globalConfig: PublicKey;
  let depositedUtxo: Utxo;
  let withdrawOutputUtxo: Utxo;
  let swapOutputUtxoMintB: Utxo;
  let altAddress: PublicKey;
  let jupiterAltAddress: PublicKey | null = null;
  let lightRPC: Rpc;

  const keyBasePath = path.resolve(__dirname, '../../circuits2/artifacts/transaction2_js/transaction2');

  before(async () => {
    // Connect to localnet
    connection = new Connection("http://127.0.0.1:8899", "confirmed");
    lightRPC = createRpc(
      "http://127.0.0.1:8899",
      "http://127.0.0.1:8784",
      "http://127.0.0.1:3001",
      {
        commitment: "confirmed",
      },
    );


    admin = Keypair.generate();
    recipient = Keypair.generate();
    feeRecipient = Keypair.generate();

    // Airdrop SOL to admin
    const airdropSignature = await connection.requestAirdrop(
      admin.publicKey,
      10 * LAMPORTS_PER_SOL
    );
    await connection.confirmTransaction(airdropSignature);

    const airdropS2 = await connection.requestAirdrop(
      new PublicKey("3sRYCnav8x6fFBymaFp4vpZE4zarg9ukMWEx59JBsD1S"),
      10 * LAMPORTS_PER_SOL
    );
    await connection.confirmTransaction(airdropS2);


    // Setup provider and program
    const wallet = new Wallet(admin);
    provider = new AnchorProvider(connection, wallet, {
      commitment: "confirmed",
      preflightCommitment: "confirmed",
    });
    setProvider(provider);
    program = anchor.workspace.Yona as Program<Yona>;

    // Initialize light wasm
    lightWasm = await WasmFactory.getInstance();

    // Initialize merkle tree
    globalMerkleTree = new MerkleTree(DEFAULT_HEIGHT, lightWasm);

    // Derive global config
    [globalConfig] = findGlobalConfigPDA(program.programId);

    console.log("Setup completed");
    console.log("Admin:", admin.publicKey.toString());
    console.log("Program ID:", program.programId.toString());
    console.log("Global Config:", globalConfig.toString());
  });

  it("Initialize", async () => {
    const [treeAccount] = PublicKey.findProgramAddressSync(
      [Buffer.from("merkle_tree")],
      program.programId
    );
    const [treeTokenAccount] = PublicKey.findProgramAddressSync(
      [Buffer.from("tree_token")],
      program.programId
    );

    const tx = await program.methods
      .initialize()
      .accountsStrict({
        treeAccount,
        treeTokenAccount,
        globalConfig: globalConfig,
        authority: admin.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .signers([admin])
      .rpc();

    console.log("Initialize tx:", tx);
  });

  it("Create test tokens", async () => {
    // Create mint A
    mintAddressA = await createMint(
      connection,
      admin,
      admin.publicKey,
      null,
      9 // 9 decimals
    );
    console.log("Mint A:", mintAddressA.toString());

    // Create mint B
    mintAddressB = await createMint(
      connection,
      admin,
      admin.publicKey,
      null,
      9
    );
    console.log("Mint B:", mintAddressB.toString());

    // Mint tokens to admin
    const adminTokenAccountA = await getOrCreateAssociatedTokenAccount(
      connection,
      admin,
      mintAddressA,
      admin.publicKey
    );
    await mintTo(
      connection,
      admin,
      mintAddressA,
      adminTokenAccountA.address,
      admin,
      10000 * 10 ** 9 // 10,000 tokens
    );

    const adminTokenAccountB = await getOrCreateAssociatedTokenAccount(
      connection,
      admin,
      mintAddressB,
      admin.publicKey
    );
    await mintTo(
      connection,
      admin,
      mintAddressB,
      adminTokenAccountB.address,
      admin,
      10000 * 10 ** 9
    );

    const recipientTokenAccountB = await getOrCreateAssociatedTokenAccount(
      connection,
      admin,
      mintAddressB,
      new PublicKey("3sRYCnav8x6fFBymaFp4vpZE4zarg9ukMWEx59JBsD1S")
    );
    await mintTo(
      connection,
      admin,
      mintAddressB,
      recipientTokenAccountB.address,
      admin,
      10000 * 10 ** 9
    );

    const recipientTokenAccountA = await getOrCreateAssociatedTokenAccount(
      connection,
      admin,
      mintAddressA,
      new PublicKey("3sRYCnav8x6fFBymaFp4vpZE4zarg9ukMWEx59JBsD1S")
    );
    await mintTo(
      connection,
      admin,
      mintAddressA,
      recipientTokenAccountA.address,
      admin,
      10000 * 10 ** 9
    );

    // Create fee recipient ATAs for both mints
    await getOrCreateAssociatedTokenAccount(
      connection,
      admin,
      mintAddressA,
      feeRecipient.publicKey
    );
    await getOrCreateAssociatedTokenAccount(
      connection,
      admin,
      mintAddressB,
      feeRecipient.publicKey
    );

    console.log("Tokens minted");
  });

  it("Create Address Lookup Table", async () => {
    // Get protocol addresses for ALT
    const protocolAddresses = getTestProtocolAddresses(
      program.programId,
      admin.publicKey,
      feeRecipient.publicKey,
    );

    // Get Light Protocol state tree accounts
    const lightStaticAccounts = defaultStaticAccountsStruct();
    const lightTreeAccounts = defaultTestStateTreeAccounts();
    const lightAddresses = [
      LightSystemProgram.programId,
      lightStaticAccounts.registeredProgramPda,
      lightStaticAccounts.noopProgram,
      lightStaticAccounts.accountCompressionProgram,
      lightStaticAccounts.accountCompressionAuthority,
      lightTreeAccounts.addressTree,
      lightTreeAccounts.addressQueue,
      lightTreeAccounts.merkleTree,
      lightTreeAccounts.nullifierQueue,
    ];

    // Add mint addresses and Light Protocol addresses
    const allAddresses = [
      ...protocolAddresses,
      mintAddressA,
      mintAddressB,
      getAssociatedTokenAddressSync(mintAddressA, globalConfig, true),
      getAssociatedTokenAddressSync(NATIVE_MINT, globalConfig, true),
      getAssociatedTokenAddressSync(mintAddressB, globalConfig, true),
      ...lightAddresses,
    ];

    altAddress = await createGlobalTestALT(
      connection,
      admin,
      allAddresses
    );

    console.log("ALT created:", altAddress.toString());
    console.log("Light Protocol addresses added to ALT");
  });

  it("Deposit mintA", async () => {
    const depositAmount = 100000;
    const depositFee = new BN(calculateDepositFee(depositAmount));

    const reserveTokenAccount = getAssociatedTokenAddressSync(
      mintAddressA,
      globalConfig,
      true
    );
    const reserveTokenAccountB = getAssociatedTokenAddressSync(
      mintAddressB,
      globalConfig,
      true
    );

    // Create reserve token account if doesn't exist
    const reserveAccountInfo = await connection.getAccountInfo(reserveTokenAccount);
    if (!reserveAccountInfo) {
      const createAtaIx = createAssociatedTokenAccountInstruction(
        admin.publicKey,
        reserveTokenAccount,
        globalConfig,
        mintAddressA
      );
      const createAtaIxB = createAssociatedTokenAccountInstruction(
        admin.publicKey,
        reserveTokenAccountB,
        globalConfig,
        mintAddressB
      );
      const createAtaIxNative = createAssociatedTokenAccountInstruction(
        admin.publicKey,
        getAssociatedTokenAddressSync(NATIVE_MINT, globalConfig, true),
        globalConfig,
        NATIVE_MINT
      );
      const createAtaTx = new Transaction().add(createAtaIx, createAtaIxB, createAtaIxNative);
      await sendAndConfirmTransaction(connection, createAtaTx, [admin], {});
    }

    const depositExtData: ExtData = {
      recipient: reserveTokenAccount,
      extAmount: new BN(depositAmount),
      encryptedOutput: Buffer.from("1"),
      fee: depositFee,
      feeRecipient: getAssociatedTokenAddressSync(mintAddressA, feeRecipient.publicKey, true),
      mintAddressA: mintAddressA,
      mintAddressB: mintAddressA,
    };

    const depositInputs = [
      new Utxo({ lightWasm, mintAddress: mintAddressA.toString() }),
      new Utxo({ lightWasm, mintAddress: mintAddressA.toString() }),
    ];

    const publicAmount = depositExtData.extAmount.sub(depositFee);
    const publicAmountNumber = publicAmount.add(FIELD_SIZE).mod(FIELD_SIZE);
    const outputAmount = publicAmountNumber.toString();

    const depositOutputs = [
      new Utxo({
        lightWasm,
        amount: outputAmount,
        index: globalMerkleTree._layers[0].length,
        mintAddress: mintAddressA.toString()
      }),
      new Utxo({
        lightWasm,
        amount: 0,
        mintAddress: mintAddressA.toString()
      })
    ];

    const depositInputMerklePathIndices = depositInputs.map(() => 0);
    const depositInputMerklePathElements = depositInputs.map(() => {
      return [...new Array(globalMerkleTree.levels).fill(0)];
    });

    const depositInputNullifiers = await Promise.all(depositInputs.map(x => x.getNullifier()));
    const depositOutputCommitments = await Promise.all(depositOutputs.map(x => x.getCommitment()));
    const depositRoot = globalMerkleTree.root();
    console.log("depositRoot:", depositRoot);
    console.log("=== ExtData Debug ===");
    console.log("recipient:", depositExtData.recipient.toString());
    console.log("extAmount:", depositExtData.extAmount.toString());
    console.log("encryptedOutput length:", depositExtData.encryptedOutput.length);
    console.log("fee:", depositExtData.fee.toString());
    console.log("feeRecipient:", depositExtData.feeRecipient.toString());
    console.log("mintAddressA:", depositExtData.mintAddressA.toString());
    console.log("mintAddressB:", depositExtData.mintAddressB.toString());
    const depositExtDataHash = getExtDataHash(depositExtData);
    console.log("depositExtDataHash:", Buffer.from(depositExtDataHash).toString('hex'));

    const depositInput: ProofInput = {
      root: depositRoot,
      inputNullifier: depositInputNullifiers,
      outputCommitment: depositOutputCommitments,
      publicAmount0: publicAmountNumber.toString(),
      publicAmount1: "0",
      extDataHash: depositExtDataHash,
      mintAddress0: publicKeyToFieldElement(mintAddressA),
      mintAddress1: publicKeyToFieldElement(mintAddressA),
      inAmount: depositInputs.map(x => x.amount.toString(10)),
      inMintAddress: depositInputs.map(x => x.mintAddress),
      inPrivateKey: depositInputs.map(x => x.keypair.privkey),
      inBlinding: depositInputs.map(x => x.blinding.toString(10)),
      inPathIndices: depositInputMerklePathIndices,
      inPathElements: depositInputMerklePathElements,
      outAmount: depositOutputs.map(x => x.amount.toString(10)),
      outMintAddress: depositOutputs.map(x => x.mintAddress),
      outPubkey: depositOutputs.map(x => x.keypair.pubkey),
      outBlinding: depositOutputs.map(x => x.blinding.toString(10)),
    };

    const depositProofResult = await prove(depositInput, keyBasePath);
    const depositProofInBytes = parseProofToBytesArray(depositProofResult.proof, true);
    const depositInputsInBytes = parseToBytesArray(depositProofResult.publicSignals);

    const depositProofToSubmit: ProofToSubmit = {
      proofA: depositProofInBytes.proofA,
      proofB: depositProofInBytes.proofB.flat(),
      proofC: depositProofInBytes.proofC,
      root: depositInputsInBytes[0],
      publicAmount0: depositInputsInBytes[1],
      publicAmount1: depositInputsInBytes[2],
      extDataHash: depositInputsInBytes[3],
      inputNullifiers: [depositInputsInBytes[6], depositInputsInBytes[7]],
      outputCommitments: [depositInputsInBytes[8], depositInputsInBytes[9]],
    };

    // Build and send deposit transaction with Light Protocol nullifiers
    console.log("Building deposit with Light Protocol nullifiers...");
    const depositTx = await buildDepositWithLightNullifiersInstruction(
      program,
      depositProofToSubmit,
      depositExtData,
      admin.publicKey,
      mintAddressA,
      lightRPC
    );

    await sendTransactionWithALT(
      connection,
      depositTx,
      admin,
      [],
      [altAddress],
      1400000
    );
    console.log("Deposit with Light Protocol nullifiers successful!");

    

    // Update merkle tree
    for (const commitment of depositOutputCommitments) {
      globalMerkleTree.insert(commitment);
    }

    depositedUtxo = depositOutputs[0];
    console.log("depositedUtxo:", depositedUtxo.amount.toString());
  });

  it("Withdraw", async () => {
    const withdrawalAmount = 50000;
    const withdrawalFee = new BN(calculateWithdrawalFee(withdrawalAmount));

    const recipientTokenAccount = await getOrCreateAssociatedTokenAccount(
      connection,
      admin,
      mintAddressA,
      recipient.publicKey
    );

    const feeRecipientTokenAccount = await getOrCreateAssociatedTokenAccount(
      connection,
      admin,
      mintAddressA,
      feeRecipient.publicKey
    );

    const withdrawExtData: ExtData = {
      recipient: recipient.publicKey,
      extAmount: new BN(-withdrawalAmount),
      encryptedOutput: Buffer.from(""),
      fee: withdrawalFee,
      feeRecipient: feeRecipientTokenAccount.address,
      mintAddressA: mintAddressA,
      mintAddressB: mintAddressA,
    };

    const withdrawInputs = [
      depositedUtxo,
      new Utxo({ lightWasm, mintAddress: mintAddressA.toString() }),
    ];

    const inputsSum = withdrawInputs.reduce((sum, x) => sum.add(x.amount), new BN(0));
    const publicAmount0 = new BN(-withdrawalAmount).sub(withdrawalFee).add(FIELD_SIZE).mod(FIELD_SIZE);
    const remainingAmount = inputsSum.sub(new BN(withdrawalAmount)).sub(withdrawalFee);

    const withdrawOutputs = [
      new Utxo({
        lightWasm,
        amount: remainingAmount.toString(),
        index: globalMerkleTree._layers[0].length,
        mintAddress: mintAddressA.toString()
      }),
      new Utxo({
        lightWasm,
        amount: 0,
        mintAddress: mintAddressA.toString()
      })
    ];

    const withdrawInputMerklePathIndices = [];
    const withdrawInputMerklePathElements = [];

    for (let i = 0; i < withdrawInputs.length; i++) {
      const input = withdrawInputs[i];
      if (input.amount.gt(new BN(0))) {
        const commitment = await input.getCommitment();
        input.index = globalMerkleTree.indexOf(commitment);
        if (input.index === -1) {
          input.index = 0;
        }
        withdrawInputMerklePathIndices.push(input.index);
        withdrawInputMerklePathElements.push(globalMerkleTree.path(input.index).pathElements);
      } else {
        withdrawInputMerklePathIndices.push(0);
        withdrawInputMerklePathElements.push(new Array(globalMerkleTree.levels).fill(0));
      }
    }

    const withdrawInputNullifiers = await Promise.all(withdrawInputs.map(x => x.getNullifier()));
    const withdrawOutputCommitments = await Promise.all(withdrawOutputs.map(x => x.getCommitment()));
    const withdrawRoot = globalMerkleTree.root();
    const withdrawExtDataHash = getExtDataHash(withdrawExtData);

    const withdrawInput: ProofInput = {
      root: withdrawRoot,
      inputNullifier: withdrawInputNullifiers,
      outputCommitment: withdrawOutputCommitments,
      publicAmount0: publicAmount0.toString(),
      publicAmount1: "0",
      extDataHash: withdrawExtDataHash,
      mintAddress0: publicKeyToFieldElement(mintAddressA),
      mintAddress1: publicKeyToFieldElement(mintAddressA),
      inAmount: withdrawInputs.map(x => x.amount.toString(10)),
      inMintAddress: withdrawInputs.map(x => x.mintAddress),
      inPrivateKey: withdrawInputs.map(x => x.keypair.privkey),
      inBlinding: withdrawInputs.map(x => x.blinding.toString(10)),
      inPathIndices: withdrawInputMerklePathIndices,
      inPathElements: withdrawInputMerklePathElements,
      outAmount: withdrawOutputs.map(x => x.amount.toString(10)),
      outMintAddress: withdrawOutputs.map(x => x.mintAddress),
      outPubkey: withdrawOutputs.map(x => x.keypair.pubkey),
      outBlinding: withdrawOutputs.map(x => x.blinding.toString(10)),
    };

    const withdrawProofResult = await prove(withdrawInput, keyBasePath);
    const withdrawProofInBytes = parseProofToBytesArray(withdrawProofResult.proof, true);
    const withdrawInputsInBytes = parseToBytesArray(withdrawProofResult.publicSignals);

    const withdrawProofToSubmit: ProofToSubmit = {
      proofA: withdrawProofInBytes.proofA,
      proofB: withdrawProofInBytes.proofB.flat(),
      proofC: withdrawProofInBytes.proofC,
      root: withdrawInputsInBytes[0],
      publicAmount0: withdrawInputsInBytes[1],
      publicAmount1: withdrawInputsInBytes[2],
      extDataHash: withdrawInputsInBytes[3],
      inputNullifiers: [withdrawInputsInBytes[6], withdrawInputsInBytes[7]],
      outputCommitments: [withdrawInputsInBytes[8], withdrawInputsInBytes[9]],
    };

    // Build and send withdraw transaction with Light Protocol nullifiers
    console.log("Building withdraw with Light Protocol nullifiers...");
    const withdrawTx = await buildWithdrawWithLightNullifiersInstruction(
      program,
      withdrawProofToSubmit,
      withdrawExtData,
      admin.publicKey,
      mintAddressA,
      lightRPC
    );

    await sendTransactionWithALT(
      connection,
      withdrawTx,
      admin,
      [],
      [altAddress],
      1400000
    );
    console.log("Withdraw with Light Protocol nullifiers successful!");

    for (const commitment of withdrawOutputCommitments) {
      globalMerkleTree.insert(commitment);
    }

    withdrawOutputUtxo = withdrawOutputs[0];
    console.log("Withdraw successful, remaining UTXO:", withdrawOutputUtxo.amount.toString());
  });

  // it("Swap mintA to mintB", async () => {
  //   const swapAmount = withdrawOutputUtxo.amount;
  //   const swapFee = new BN(calculateWithdrawalFee(swapAmount.toNumber()));
  //   const minAmountOut = new BN(1000);

  //   const feeRecipientTokenAccount = await getOrCreateAssociatedTokenAccount(
  //     connection,
  //     admin,
  //     mintAddressB,
  //     feeRecipient.publicKey
  //   );

  //   const swapData: SwapData = {
  //     extAmount: new BN(0),
  //     extMinAmountOut: minAmountOut,
  //     encryptedOutput: Buffer.from(""),
  //     fee: swapFee,
  //     feeRecipient: feeRecipient.publicKey,
  //     mintAddressA: mintAddressA,
  //     mintAddressB: mintAddressB,
  //   };

  //   const swapInputs = [
  //     withdrawOutputUtxo,
  //     new Utxo({ lightWasm, mintAddress: mintAddressA.toString() }),
  //   ];

  //   const inputsSum = swapInputs.reduce((sum, x) => sum.add(x.amount), new BN(0));
  //   const outputAmount = inputsSum.sub(swapFee);

  //   const swapOutputs = [
  //     new Utxo({
  //       lightWasm,
  //       amount: outputAmount.toString(),
  //       index: globalMerkleTree._layers[0].length,
  //       mintAddress: mintAddressB.toString()
  //     }),
  //     new Utxo({
  //       lightWasm,
  //       amount: 0,
  //       mintAddress: mintAddressB.toString()
  //     })
  //   ];

  //   const swapInputMerklePathIndices = [];
  //   const swapInputMerklePathElements = [];

  //   for (let i = 0; i < swapInputs.length; i++) {
  //     const input = swapInputs[i];
  //     if (input.amount.gt(new BN(0))) {
  //       const commitment = await input.getCommitment();
  //       input.index = globalMerkleTree.indexOf(commitment);
  //       if (input.index === -1) {
  //         input.index = 0;
  //       }
  //       swapInputMerklePathIndices.push(input.index);
  //       swapInputMerklePathElements.push(globalMerkleTree.path(input.index).pathElements);
  //     } else {
  //       swapInputMerklePathIndices.push(0);
  //       swapInputMerklePathElements.push(new Array(globalMerkleTree.levels).fill(0));
  //     }
  //   }

  //   const swapInputNullifiers = await Promise.all(swapInputs.map(x => x.getNullifier()));
  //   const swapOutputCommitments = await Promise.all(swapOutputs.map(x => x.getCommitment()));
  //   const swapRoot = globalMerkleTree.root();
  //   const swapExtDataHash = getSwapExtDataHash(swapData);

  //   const publicAmount0 = new BN(0).sub(swapFee).add(FIELD_SIZE).mod(FIELD_SIZE);

  //   const swapInput: ProofInput = {
  //     root: swapRoot,
  //     inputNullifier: swapInputNullifiers,
  //     outputCommitment: swapOutputCommitments,
  //     publicAmount0: publicAmount0.toString(),
  //     publicAmount1: "0",
  //     extDataHash: swapExtDataHash,
  //     mintAddress0: publicKeyToFieldElement(mintAddressA),
  //     mintAddress1: publicKeyToFieldElement(mintAddressB),
  //     inAmount: swapInputs.map(x => x.amount.toString(10)),
  //     inMintAddress: swapInputs.map(x => x.mintAddress),
  //     inPrivateKey: swapInputs.map(x => x.keypair.privkey),
  //     inBlinding: swapInputs.map(x => x.blinding.toString(10)),
  //     inPathIndices: swapInputMerklePathIndices,
  //     inPathElements: swapInputMerklePathElements,
  //     outAmount: swapOutputs.map(x => x.amount.toString(10)),
  //     outMintAddress: swapOutputs.map(x => x.mintAddress),
  //     outPubkey: swapOutputs.map(x => x.keypair.pubkey),
  //     outBlinding: swapOutputs.map(x => x.blinding.toString(10)),
  //   };

  //   const swapProofResult = await prove(swapInput, keyBasePath);
  //   const swapProofInBytes = parseProofToBytesArray(swapProofResult.proof, true);
  //   const swapInputsInBytes = parseToBytesArray(swapProofResult.publicSignals);

  //   const swapProofToSubmit: ProofToSubmit = {
  //     proofA: swapProofInBytes.proofA,
  //     proofB: swapProofInBytes.proofB.flat(),
  //     proofC: swapProofInBytes.proofC,
  //     root: swapInputsInBytes[0],
  //     publicAmount0: swapInputsInBytes[1],
  //     publicAmount1: swapInputsInBytes[2],
  //     extDataHash: swapInputsInBytes[3],
  //     inputNullifiers: [swapInputsInBytes[6], swapInputsInBytes[7]],
  //     outputCommitments: [swapInputsInBytes[8], swapInputsInBytes[9]],
  //   };

  //   console.log("Building swap with Light Protocol nullifiers...");
  //   const swapTx = await buildSwapWithLightNullifiersInstruction(
  //     program,
  //     swapProofToSubmit,
  //     swapData,
  //     admin.publicKey,
  //     mintAddressA,
  //     mintAddressB,
  //     lightRPC
  //   );

  //   const txSig = await sendTransactionWithALT(
  //     connection,
  //     swapTx,
  //     admin,
  //     [],
  //     [altAddress],
  //     1400000
  //   );
  //   console.log("Swap with Light Protocol nullifiers successful! Tx:", txSig);

  //   // Get transaction details to check size
  //   const txDetails = await connection.getTransaction(txSig, {
  //     maxSupportedTransactionVersion: 0,
  //   });
  //   if (txDetails) {
  //     const txSize = txDetails.transaction.message.serialize().length;
  //     console.log("Transaction size:", txSize, "bytes");
  //     console.log("Transaction compute units used:", txDetails.meta?.computeUnitsConsumed);
  //   }

  //   for (const commitment of swapOutputCommitments) {
  //     globalMerkleTree.insert(commitment);
  //   }

  //   swapOutputUtxoMintB = swapOutputs[0];
  //   console.log("Swap successful, output UTXO (mintB):", swapOutputUtxoMintB.amount.toString());
  // });

  it("Should fail on double-spend (reusing nullifier)", async () => {
    // Try to spend the same UTXO again (depositedUtxo was already spent in withdraw)
    const withdrawalAmount = 10000;
    const withdrawalFee = new BN(calculateWithdrawalFee(withdrawalAmount));

    const recipientTokenAccount = await getOrCreateAssociatedTokenAccount(
      connection,
      admin,
      mintAddressA,
      recipient.publicKey
    );

    const feeRecipientTokenAccount = await getOrCreateAssociatedTokenAccount(
      connection,
      admin,
      mintAddressA,
      feeRecipient.publicKey
    );

    const withdrawExtData: ExtData = {
      recipient: recipient.publicKey,
      extAmount: new BN(-withdrawalAmount),
      encryptedOutput: Buffer.from(""),
      fee: withdrawalFee,
      feeRecipient: feeRecipientTokenAccount.address,
      mintAddressA: mintAddressA,
      mintAddressB: mintAddressA,
    };

    const withdrawInputs = [
      depositedUtxo, // This UTXO was already spent in the first withdraw test
      new Utxo({ lightWasm, mintAddress: mintAddressA.toString() }),
    ];

    const inputsSum = withdrawInputs.reduce((sum, x) => sum.add(x.amount), new BN(0));
    const publicAmount0 = new BN(-withdrawalAmount).sub(withdrawalFee).add(FIELD_SIZE).mod(FIELD_SIZE);
    const remainingAmount = inputsSum.sub(new BN(withdrawalAmount)).sub(withdrawalFee);

    const withdrawOutputs = [
      new Utxo({
        lightWasm,
        amount: remainingAmount.toString(),
        index: globalMerkleTree._layers[0].length,
        mintAddress: mintAddressA.toString()
      }),
      new Utxo({
        lightWasm,
        amount: 0,
        mintAddress: mintAddressA.toString()
      })
    ];

    const withdrawInputMerklePathIndices = [];
    const withdrawInputMerklePathElements = [];

    for (let i = 0; i < withdrawInputs.length; i++) {
      const input = withdrawInputs[i];
      if (input.amount.gt(new BN(0))) {
        const commitment = await input.getCommitment();
        input.index = globalMerkleTree.indexOf(commitment);
        if (input.index === -1) {
          input.index = 0;
        }
        withdrawInputMerklePathIndices.push(input.index);
        withdrawInputMerklePathElements.push(globalMerkleTree.path(input.index).pathElements);
      } else {
        withdrawInputMerklePathIndices.push(0);
        withdrawInputMerklePathElements.push(new Array(globalMerkleTree.levels).fill(0));
      }
    }

    const withdrawInputNullifiers = await Promise.all(withdrawInputs.map(x => x.getNullifier()));
    const withdrawOutputCommitments = await Promise.all(withdrawOutputs.map(x => x.getCommitment()));
    const withdrawRoot = globalMerkleTree.root();
    const withdrawExtDataHash = getExtDataHash(withdrawExtData);

    const withdrawInput: ProofInput = {
      root: withdrawRoot,
      inputNullifier: withdrawInputNullifiers,
      outputCommitment: withdrawOutputCommitments,
      publicAmount0: publicAmount0.toString(),
      publicAmount1: "0",
      extDataHash: withdrawExtDataHash,
      mintAddress0: publicKeyToFieldElement(mintAddressA),
      mintAddress1: publicKeyToFieldElement(mintAddressA),
      inAmount: withdrawInputs.map(x => x.amount.toString(10)),
      inMintAddress: withdrawInputs.map(x => x.mintAddress),
      inPrivateKey: withdrawInputs.map(x => x.keypair.privkey),
      inBlinding: withdrawInputs.map(x => x.blinding.toString(10)),
      inPathIndices: withdrawInputMerklePathIndices,
      inPathElements: withdrawInputMerklePathElements,
      outAmount: withdrawOutputs.map(x => x.amount.toString(10)),
      outMintAddress: withdrawOutputs.map(x => x.mintAddress),
      outPubkey: withdrawOutputs.map(x => x.keypair.pubkey),
      outBlinding: withdrawOutputs.map(x => x.blinding.toString(10)),
    };

    const withdrawProofResult = await prove(withdrawInput, keyBasePath);
    const withdrawProofInBytes = parseProofToBytesArray(withdrawProofResult.proof, true);
    const withdrawInputsInBytes = parseToBytesArray(withdrawProofResult.publicSignals);

    const withdrawProofToSubmit: ProofToSubmit = {
      proofA: withdrawProofInBytes.proofA,
      proofB: withdrawProofInBytes.proofB.flat(),
      proofC: withdrawProofInBytes.proofC,
      root: withdrawInputsInBytes[0],
      publicAmount0: withdrawInputsInBytes[1],
      publicAmount1: withdrawInputsInBytes[2],
      extDataHash: withdrawInputsInBytes[3],
      inputNullifiers: [withdrawInputsInBytes[6], withdrawInputsInBytes[7]],
      outputCommitments: [withdrawInputsInBytes[8], withdrawInputsInBytes[9]],
    };

    console.log("Attempting double-spend with same nullifier...");
    try {
      const withdrawTx = await buildWithdrawWithLightNullifiersInstruction(
        program,
        withdrawProofToSubmit,
        withdrawExtData,
        admin.publicKey,
        mintAddressA,
        lightRPC
      );

      await sendTransactionWithALT(
        connection,
        withdrawTx,
        admin,
        [],
        [altAddress],
        1400000
      );

      // If we get here, the test should fail
      expect.fail("Double-spend should have been rejected");
    } catch (error: any) {
      console.log("Double-spend correctly rejected!");
      console.log("Error:", error.message);
      // The error should be from Light Protocol indicating the address already exists
      expect(error.message).to.satisfy((msg: string) => 
        msg.includes("AddressAlreadyExists") || 
        msg.includes("already exists") ||
        msg.includes("failed") ||
        msg.includes("error")
      );
    }
  });
});
