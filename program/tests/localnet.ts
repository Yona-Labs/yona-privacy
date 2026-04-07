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
import { buildDepositInstruction, buildWithdrawInstruction, buildSwapInstruction, sendTransactionWithALT, createSwapExtDataMinified } from "./instructions";
import { Utxo } from "./lib/utxo";
import { DEFAULT_HEIGHT, FIELD_SIZE, ROOT_HISTORY_SIZE, ZERO_BYTES, DEPOSIT_FEE_RATE, WITHDRAW_FEE_RATE } from "./lib/constants";
import { getExtDataHash, getSwapExtDataHash, publicKeyToFieldElement } from "./lib/utils";
import { parseProofToBytesArray, parseToBytesArray, prove } from "./lib/prover";
import { findGlobalConfigPDA } from "./lib/derive";
import path from "path";
import { ExtData, ProofToSubmit, ProofInput, SwapData } from "./lib/types";
import { createGlobalTestALT, createNewALT, getTestProtocolAddresses } from "./lib/test_alt";
import { buildSwapWithJupiter } from "./jup";

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

  const keyBasePath = path.resolve(__dirname, '../../circuits2/artifacts/transaction2_js/transaction2');

  before(async () => {
    // Connect to localnet
    connection = new Connection("http://127.0.0.1:8899", "confirmed");

    // Load keypairs
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

    console.log("Tokens minted");
  });

  it("Create Address Lookup Table", async () => {
    // Get protocol addresses for ALT
    const protocolAddresses = getTestProtocolAddresses(
      program.programId,
      admin.publicKey,
      feeRecipient.publicKey,
    );

    // Add mint addresses
    const allAddresses = [
      ...protocolAddresses,
      mintAddressA,
      mintAddressB,
      getAssociatedTokenAddressSync(mintAddressA, globalConfig, true),
      getAssociatedTokenAddressSync(NATIVE_MINT, globalConfig, true),
      getAssociatedTokenAddressSync(mintAddressB, globalConfig, true),
    ];

    altAddress = await createGlobalTestALT(
      connection,
      admin,
      allAddresses
    );

    console.log("ALT created:", altAddress.toString());
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
      await sendAndConfirmTransaction(connection, createAtaTx, [admin]);
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

    // Build and send deposit transaction with ALT
    const depositTx = await buildDepositInstruction(
      program,
      depositProofToSubmit,
      depositExtData,
      admin.publicKey,
      mintAddressA
    );

    await sendTransactionWithALT(
      connection,
      depositTx,
      admin,
      [],
      [altAddress],
      1400000
    );

    

    // Update merkle tree
    for (const commitment of depositOutputCommitments) {
      globalMerkleTree.insert(commitment);
    }

    depositedUtxo = depositOutputs[0];
    console.log("depositedUtxo:", depositedUtxo.amount.toString());
  });

  // it("Swap mintA to mintB", async () => {
  //   if (!depositedUtxo) {
  //     throw new Error("depositedUtxo is not defined. Run deposit test first.");
  //   }

  //   // Transfer some mintB tokens to reserve for swap
  //   const adminTokenAccountB = await getOrCreateAssociatedTokenAccount(
  //     connection,
  //     admin,
  //     mintAddressB,
  //     admin.publicKey
  //   );

  //   const reserveTokenAccountB = getAssociatedTokenAddressSync(
  //     mintAddressB,
  //     globalConfig,
  //     true
  //   );

  //   // Create reserve token account B if doesn't exist
  //   const reserveAccountBInfo = await connection.getAccountInfo(reserveTokenAccountB);
  //   if (!reserveAccountBInfo) {
  //     const createAtaIx = createAssociatedTokenAccountInstruction(
  //       admin.publicKey,
  //       reserveTokenAccountB,
  //       globalConfig,
  //       mintAddressB
  //     );
  //     const createAtaTx = new Transaction().add(createAtaIx);
  //     await sendAndConfirmTransaction(connection, createAtaTx, [admin]);
  //     console.log("Reserve token account B created");
  //   }

  //   const swapAmountIn = 200;
  //   const swapMinAmountOut = 100;
  //   const swapFee = new BN(0);

  //   const swapExtData: SwapData = {
  //     extAmount: new BN(-swapAmountIn),
  //     extMinAmountOut: new BN(swapMinAmountOut),
  //     encryptedOutput1: Buffer.from("swapEncryptedOutput1"),
  //     encryptedOutput2: Buffer.from("swapEncryptedOutput2"),
  //     fee: swapFee,
  //     feeRecipient: getAssociatedTokenAddressSync(mintAddressA, feeRecipient.publicKey, true),
  //     mintAddressA: mintAddressA,
  //     mintAddressB: mintAddressB,
  //   };

  //   const swapInputs = [
  //     depositedUtxo,
  //     new Utxo({ lightWasm, mintAddress: publicKeyToFieldElement(mintAddressB) })
  //   ];

  //   const inputsSum = swapInputs.reduce((sum, x) => sum.add(x.amount), new BN(0));

  //   const publicAmount0 = new BN(-swapAmountIn).sub(swapFee).add(FIELD_SIZE).mod(FIELD_SIZE);
  //   const publicAmount1 = new BN(swapMinAmountOut).add(FIELD_SIZE).mod(FIELD_SIZE);

  //   const remainingAmountMintA = inputsSum.sub(new BN(swapAmountIn)).sub(swapFee);
  //   const swappedAmountMintB = new BN(swapMinAmountOut);

  //   const swapOutputs = [
  //     new Utxo({
  //       lightWasm,
  //       amount: remainingAmountMintA.toString(),
  //       index: globalMerkleTree._layers[0].length,
  //       mintAddress: publicKeyToFieldElement(mintAddressA)
  //     }),
  //     new Utxo({
  //       lightWasm,
  //       amount: swappedAmountMintB.toString(),
  //       index: globalMerkleTree._layers[0].length + 1,
  //       mintAddress: publicKeyToFieldElement(mintAddressB)
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
  //   const swapExtDataHash = getSwapExtDataHash(swapExtData);

  //   const swapInput: ProofInput = {
  //     root: swapRoot,
  //     inputNullifier: swapInputNullifiers,
  //     outputCommitment: swapOutputCommitments,
  //     publicAmount0: publicAmount0.toString(),
  //     publicAmount1: publicAmount1.toString(),
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

  //   console.log("Generating swap proof...");
  //   const swapProofResult = await prove(swapInput, keyBasePath);
  //   const swapProofInBytes = parseProofToBytesArray(swapProofResult.proof);
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

  //   console.log("Swap proof generated, sending transaction with ALT...");

  //   const swapTx = await buildSwapInstruction(
  //     program,
  //     swapProofToSubmit,
  //     swapExtData,
  //     admin.publicKey,
  //     mintAddressA,
  //     mintAddressB
  //   );

  //   await sendTransactionWithALT(
  //     connection,
  //     swapTx,
  //     admin,
  //     [],
  //     altAddress,
  //     1400000
  //   );

  //   console.log("Swap successful - swapped mintA to mintB");

  //   // Update merkle tree
  //   for (const commitment of swapOutputCommitments) {
  //     globalMerkleTree.insert(commitment);
  //   }

  //   swapOutputUtxoMintB = swapOutputs[1];
  //   withdrawOutputUtxo = swapOutputs[0];
  //   console.log("swapOutputUtxoMintB:", swapOutputUtxoMintB.amount.toString());
  //   console.log("withdrawOutputUtxo (remaining mintA):", withdrawOutputUtxo.amount.toString());
  // });

  // it("Withdraw mintB", async () => {
  //   if (!swapOutputUtxoMintB) {
  //     throw new Error("swapOutputUtxoMintB is not defined. Run swap test first.");
  //   }

  //   const withdrawAmount = 3350;
  //   const withdrawFee = new BN(calculateWithdrawalFee(withdrawAmount));

  //   const recipientTokenAccount = await getOrCreateAssociatedTokenAccount(
  //     connection,
  //     admin,
  //     mintAddressB,
  //     recipient.publicKey
  //   );

  //   const withdrawExtData: ExtData = {
  //     recipient: recipientTokenAccount.address,
  //     extAmount: new BN(-withdrawAmount),
  //     encryptedOutput1: Buffer.from("withdrawEncryptedOutput1"),
  //     encryptedOutput2: Buffer.from("withdrawEncryptedOutput2"),
  //     fee: withdrawFee,
  //     feeRecipient: getAssociatedTokenAddressSync(mintAddressB, feeRecipient.publicKey, true),
  //     mintAddressA: mintAddressB,
  //     mintAddressB: mintAddressB,
  //   };

  //   const withdrawInputs = [
  //     swapOutputUtxoMintB,
  //     new Utxo({ lightWasm, mintAddress: publicKeyToFieldElement(mintAddressB) })
  //   ];

  //   const inputsSum = withdrawInputs.reduce((sum, x) => sum.add(x.amount), new BN(0));
  //   const publicAmount = new BN(-withdrawAmount).sub(withdrawFee).add(FIELD_SIZE).mod(FIELD_SIZE);
  //   const remainingAmount = inputsSum.sub(new BN(withdrawAmount)).sub(withdrawFee);

  //   const withdrawOutputs = [
  //     new Utxo({
  //       lightWasm,
  //       amount: remainingAmount.toString(),
  //       index: globalMerkleTree._layers[0].length,
  //       mintAddress: publicKeyToFieldElement(mintAddressB)
  //     }),
  //     new Utxo({
  //       lightWasm,
  //       amount: 0,
  //       mintAddress: publicKeyToFieldElement(mintAddressB)
  //     })
  //   ];

  //   const withdrawInputMerklePathIndices = [];
  //   const withdrawInputMerklePathElements = [];

  //   for (let i = 0; i < withdrawInputs.length; i++) {
  //     const input = withdrawInputs[i];
  //     if (input.amount.gt(new BN(0))) {
  //       const commitment = await input.getCommitment();
  //       input.index = globalMerkleTree.indexOf(commitment);
  //       if (input.index === -1) {
  //         throw new Error(`Input ${i} commitment not found in merkle tree`);
  //       }
  //       withdrawInputMerklePathIndices.push(input.index);
  //       withdrawInputMerklePathElements.push(globalMerkleTree.path(input.index).pathElements);
  //     } else {
  //       withdrawInputMerklePathIndices.push(0);
  //       withdrawInputMerklePathElements.push(new Array(globalMerkleTree.levels).fill(0));
  //     }
  //   }

  //   const withdrawInputNullifiers = await Promise.all(withdrawInputs.map(x => x.getNullifier()));
  //   const withdrawOutputCommitments = await Promise.all(withdrawOutputs.map(x => x.getCommitment()));
  //   const withdrawRoot = globalMerkleTree.root();
  //   const withdrawExtDataHash = getExtDataHash(withdrawExtData);

  //   const withdrawInput: ProofInput = {
  //     root: withdrawRoot,
  //     inputNullifier: withdrawInputNullifiers,
  //     outputCommitment: withdrawOutputCommitments,
  //     publicAmount0: publicAmount.toString(),
  //     publicAmount1: "0",
  //     extDataHash: withdrawExtDataHash,
  //     mintAddress0: publicKeyToFieldElement(mintAddressB),
  //     mintAddress1: publicKeyToFieldElement(mintAddressB),
  //     inAmount: withdrawInputs.map(x => x.amount.toString(10)),
  //     inMintAddress: withdrawInputs.map(x => x.mintAddress),
  //     inPrivateKey: withdrawInputs.map(x => x.keypair.privkey),
  //     inBlinding: withdrawInputs.map(x => x.blinding.toString(10)),
  //     inPathIndices: withdrawInputMerklePathIndices,
  //     inPathElements: withdrawInputMerklePathElements,
  //     outAmount: withdrawOutputs.map(x => x.amount.toString(10)),
  //     outMintAddress: withdrawOutputs.map(x => x.mintAddress),
  //     outPubkey: withdrawOutputs.map(x => x.keypair.pubkey),
  //     outBlinding: withdrawOutputs.map(x => x.blinding.toString(10)),
  //   };

  //   console.log("Generating withdrawal proof...");
  //   const withdrawProofResult = await prove(withdrawInput, keyBasePath);
  //   const withdrawProofInBytes = parseProofToBytesArray(withdrawProofResult.proof);
  //   const withdrawInputsInBytes = parseToBytesArray(withdrawProofResult.publicSignals);

  //   const withdrawProofToSubmit: ProofToSubmit = {
  //     proofA: withdrawProofInBytes.proofA,
  //     proofB: withdrawProofInBytes.proofB.flat(),
  //     proofC: withdrawProofInBytes.proofC,
  //     root: withdrawInputsInBytes[0],
  //     publicAmount0: withdrawInputsInBytes[1],
  //     publicAmount1: withdrawInputsInBytes[2],
  //     extDataHash: withdrawInputsInBytes[3],
  //     inputNullifiers: [withdrawInputsInBytes[6], withdrawInputsInBytes[7]],
  //     outputCommitments: [withdrawInputsInBytes[8], withdrawInputsInBytes[9]],
  //   };

  //   console.log("Withdrawal proof generated, sending transaction with ALT...");

  //   const withdrawTx = await buildWithdrawInstruction(
  //     program,
  //     withdrawProofToSubmit,
  //     withdrawExtData,
  //     admin.publicKey,
  //     mintAddressB
  //   );

  //   await sendTransactionWithALT(
  //     connection,
  //     withdrawTx,
  //     admin,
  //     [],
  //     altAddress,
  //     1400000
  //   );

  //   console.log("Withdrawal successful - withdrew mintB");

  //   // Update merkle tree
  //   for (const commitment of withdrawOutputCommitments) {
  //     globalMerkleTree.insert(commitment);
  //   }

  //   // Verify recipient received tokens
  //   const recipientBalance = await connection.getTokenAccountBalance(recipientTokenAccount.address);
  //   console.log("Recipient mintB balance:", recipientBalance.value.amount);
  //   expect(Number(recipientBalance.value.amount)).to.be.greaterThan(0);
  // });

  // it("Swap with Jupiter CPI", async () => {
  //   if (!depositedUtxo) {
  //     throw new Error("depositedUtxo is not defined. Run previous tests first.");
  //   }

  //   console.log("=== Testing Swap with Jupiter Integration ===");

  //   const swapAmountIn = 50;
  //   const swapMinAmountOut = 40;
  //   const swapFee = new BN(0);

  //   const swapExtData: SwapData = {
  //     extAmount: new BN(-swapAmountIn),
  //     extMinAmountOut: new BN(swapMinAmountOut),
  //     encryptedOutput: Buffer.from("1"),
  //     fee: swapFee,
  //     feeRecipient: getAssociatedTokenAddressSync(mintAddressA, feeRecipient.publicKey, true),
  //     mintAddressA: mintAddressA,
  //     mintAddressB: mintAddressB,
  //   };

  //   const swapInputs = [
  //     depositedUtxo,
  //     new Utxo({ lightWasm, mintAddress: publicKeyToFieldElement(mintAddressB) })
  //   ];

  //   const inputsSum = swapInputs.reduce((sum, x) => sum.add(x.amount), new BN(0));

  //   const publicAmount0 = new BN(-swapAmountIn).sub(swapFee).add(FIELD_SIZE).mod(FIELD_SIZE);
  //   const publicAmount1 = new BN(swapMinAmountOut).add(FIELD_SIZE).mod(FIELD_SIZE);

  //   const remainingAmountMintA = inputsSum.sub(new BN(swapAmountIn)).sub(swapFee);
  //   const swappedAmountMintB = new BN(swapMinAmountOut);

  //   const swapOutputs = [
  //     new Utxo({
  //       lightWasm,
  //       amount: remainingAmountMintA.toString(),
  //       index: globalMerkleTree._layers[0].length,
  //       mintAddress: publicKeyToFieldElement(mintAddressA)
  //     }),
  //     new Utxo({
  //       lightWasm,
  //       amount: swappedAmountMintB.toString(),
  //       index: globalMerkleTree._layers[0].length + 1,
  //       mintAddress: publicKeyToFieldElement(mintAddressB)
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
  //   const swapExtDataHash = getSwapExtDataHash(swapExtData);

  //   const swapInput: ProofInput = {
  //     root: swapRoot,
  //     inputNullifier: swapInputNullifiers,
  //     outputCommitment: swapOutputCommitments,
  //     publicAmount0: publicAmount0.toString(),
  //     publicAmount1: publicAmount1.toString(),
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

  //   console.log("Generating swap proof with Jupiter...");
  //   const swapProofResult = await prove(swapInput, keyBasePath);
  //   const swapProofInBytes = parseProofToBytesArray(swapProofResult.proof);
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

  //   console.log("Swap proof generated");

  //   // Test with Jupiter data and accounts (for size testing only)
  //   console.log("\n=== Testing transaction size with Jupiter data ===");

  //   let jupiterSwapDataForTest: Buffer | null = null;
  //   let jupiterRemainingAccounts: any[] = [];

  //   // try {
  //   //   // Get Jupiter data to test transaction size
  //   //   const jupiterResult = await buildSwapWithJupiterInstruction(
  //   //     program,
  //   //     swapProofToSubmit,
  //   //     createSwapExtDataMinified(swapExtData),
  //   //     swapExtData.encryptedOutput1,
  //   //     swapExtData.encryptedOutput2,
  //   //     mintAddressA,
  //   //     mintAddressB,
  //   //     swapAmountIn.toString(),
  //   //     admin.publicKey,
  //   //     50
  //   //   );

  //   //   // Extract instruction data from the built instruction
  //   //   const instructionData = jupiterResult.instructions[0].data;
  //   //   const totalAccounts = jupiterResult.instructions[0].keys.length;
  //   //   jupiterSwapDataForTest = instructionData;
  //   //   jupiterRemainingAccounts = jupiterResult.remainingAccounts;

  //   //   console.log("✅ Jupiter data fetched successfully!");
  //   //   console.log("\n📊 Size Analysis:");
  //   //   console.log("  Instruction data:", instructionData.length, "bytes");
  //   //   console.log("  Total accounts:", totalAccounts);
  //   //   console.log("  Remaining accounts:", jupiterRemainingAccounts.length);

  //   //   const estimatedTxSize = instructionData.length + (totalAccounts * 34);
  //   //   console.log("  Estimated instruction size:", estimatedTxSize, "bytes");

  //   //   // Create ALT for Jupiter accounts
  //   //   console.log("\n📋 Creating Address Lookup Table for Jupiter accounts...");

  //   //   const jupiterAccountPubkeys = jupiterRemainingAccounts.map(acc => acc.pubkey);
  //   //   if (jupiterAccountPubkeys.length > 0) {
  //   //     jupiterAltAddress = await createGlobalTestALT(
  //   //       connection,
  //   //       admin,
  //   //       jupiterAccountPubkeys
  //   //     );
  //   //     console.log("✅ Jupiter ALT created:", jupiterAltAddress.toString());
  //   //     console.log("  Compressed", jupiterAccountPubkeys.length, "accounts into ALT");
  //   //   }

  //   // } catch (error) {
  //   //   console.log("❌ Jupiter API test failed:", error.message || error);
  //   //   console.log("Continuing with mock swap...");
  //   // }
  //   // Get Jupiter swap data (without using remaining accounts)
  //   const { jupiterSwapData, remainingAccounts, jupiterProgramId } = await buildSwapWithJupiter(
  //     new PublicKey("So11111111111111111111111111111111111111112"),
  //     new PublicKey("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"),
  //     "100000000",
  //     new PublicKey("78Z82f93Xb8VhsQfmiHB6WsFzMDy4zbDKzCis8h5pFZK"),
  //     50
  //   );
  //   console.log("remainingAccounts:", remainingAccounts.map(acc => acc.pubkey.toString()));
  //   if (remainingAccounts.length > 0) {
  //     const jupiterAccountPubkeys = remainingAccounts.map(acc => acc.pubkey);
  //     jupiterAltAddress = await createNewALT(
  //       connection,
  //       admin,
  //       jupiterAccountPubkeys
  //     );
  //     console.log("✅ Jupiter ALT created:", jupiterAltAddress.toString());
  //     console.log("  Compressed", remainingAccounts.length, "accounts into ALT");
  //   }
  //   jupiterSwapDataForTest = Buffer.from(jupiterSwapData);
  //   console.log("jupiterSwapDataForTest length:", jupiterSwapDataForTest.length);

  //   console.log("\n=== Executing swap WITH Jupiter data (no remaining accounts) ===");

  //   const swapTxWithJupiter = await buildSwapInstruction(
  //     program,
  //     swapProofToSubmit,
  //     swapExtData,
  //     admin.publicKey,
  //     mintAddressA,
  //     mintAddressB,
  //     jupiterSwapDataForTest, // Pass Jupiter data
  //     remainingAccounts
  //   );

  //   console.log("✅ Jupiter data prepared!");
  //   console.log("\n📊 Size Analysis:");
  //   console.log("  Instruction data:", swapTxWithJupiter[0].data.length, "bytes");
  //   console.log("  Total accounts:", swapTxWithJupiter[0].keys.length);

  //   const altAddresses = jupiterAltAddress ? [altAddress, jupiterAltAddress] : [altAddress];

  //   const sig = await sendTransactionWithALT(
  //     connection,
  //     swapTxWithJupiter,
  //     admin,
  //     [],
  //     [altAddress, jupiterAltAddress], // Use regular ALT and Jupiter ALT
  //     1400000
  //   );
  //   console.log(sig)
  //   console.log("✅ Swap with Jupiter data successful!");

  //   console.log("\n📝 Summary:");
  //   console.log("  - Jupiter integration structure: READY");
  //   console.log("  - Instruction accepts Jupiter data: YES");
  //   console.log("  - Can pass remaining accounts: YES");
  //   console.log("  - Jupiter ALT created:", jupiterAltAddress ? "YES" : "NO");
  //   console.log("  - Transaction with ALT:", jupiterAltAddress ? "SUCCESS" : "NOT TESTED");
  //   console.log("\n💡 Next steps:");
  //   console.log("  1. Enable CPI in contract when ready");
  //   console.log("  2. Use Jupiter ALT for production transactions");
  //   console.log("  3. Jupiter accounts now fit within Solana limits!");



  //   // Update merkle tree
  //   for (const commitment of swapOutputCommitments) {
  //     globalMerkleTree.insert(commitment);
  //   }

  //   console.log("swapRoot:", swapRoot);
  //   console.log("globalMerkleTree.root():", globalMerkleTree.root());
  //   console.log("Test completed successfully!");
  // });
});

