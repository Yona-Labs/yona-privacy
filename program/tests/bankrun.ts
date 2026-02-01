import { setProvider, Program, BN } from "@coral-xyz/anchor";
import * as anchor from "@coral-xyz/anchor";
import { calculateDepositFee, calculateWithdrawalFee } from "./lib/math";
import { ProgramTestContext, BanksClient, startAnchor } from "solana-bankrun";
import { BankrunProvider } from "anchor-bankrun";
import { expect } from "chai";
import {
  PublicKey,
  Transaction,
  Keypair,
  Connection,
  clusterApiUrl,
  TransactionInstruction,
  LAMPORTS_PER_SOL,
  SystemProgram
} from "@solana/web3.js";
import {
  createAssociatedTokenAccountInstruction,
  getAssociatedTokenAddressSync,
  TOKEN_PROGRAM_ID,
} from "@solana/spl-token";
import { Yona } from "../target/types/yona";
import { LightWasm, WasmFactory } from "@lightprotocol/hasher.rs";
import { MerkleTree } from "./lib/merkle_tree";
import { buildDepositInstruction, buildWithdrawInstruction, buildSwapInstruction, executeInitialize, sendBankrunTransaction, startSetupBankrun, createAtaBankrun, transferTokenBankrun } from "./instructions";
import { Utxo } from "./lib/utxo";
import { DEFAULT_HEIGHT, FIELD_SIZE, ROOT_HISTORY_SIZE, ZERO_BYTES, DEPOSIT_FEE_RATE, WITHDRAW_FEE_RATE } from "./lib/constants";
import { getExtDataHash, getSwapExtDataHash, publicKeyToFieldElement, hashToFieldElement } from "./lib/utils";
import { parseProofToBytesArray, parseToBytesArray, prove } from "./lib/prover";
import { findCommitmentPDAs, findGlobalConfigPDA, findNullifierPDAs, findTreeTokenAccountPDA } from "./lib/derive";
import path from "path";
import { createMint } from "./lib/token";
import { createGlobalTestALT, createVersionedTransactionWithALT, getTestProtocolAddresses } from "./lib/test_alt";
import { ExtData, ProofToSubmit, ProofInput, SwapData } from "./lib/types";

describe("bankrun", () => {
  let context: ProgramTestContext;
  let provider: BankrunProvider;
  let program: Program<Yona>;
  let banksClient: BanksClient;
  let admin: Keypair;
  let mintAddressA: PublicKey;
  let mintAddressB: PublicKey;
  let lightWasm: LightWasm;
  let globalMerkleTree: MerkleTree;
  let recipient: Keypair;
  let feeRecipient: Keypair;
  let globalConfig: PublicKey;
  let depositedUtxo: Utxo;
  let depositedUtxoMintB: Utxo;
  let withdrawOutputUtxo: Utxo;
  const keyBasePath = path.resolve(__dirname, '../../circuits2/artifacts/transaction2_js/transaction2');


  before(async () => {
    context = await startAnchor("", [{ name: "yona", programId: new PublicKey("yonaMBw7KLYvQSspboB2GGAt5EsQqV28dZZasKhKGqC") }], []);
    console.log("Starting bankrun tests")
    const wallet = new anchor.Wallet(context.payer);
    provider = new BankrunProvider(context);
    anchor.setProvider(provider);

    lightWasm = await WasmFactory.getInstance();
    globalMerkleTree = new MerkleTree(DEFAULT_HEIGHT, lightWasm);

    program = anchor.workspace.Yona as Program<Yona>;
    banksClient = context.banksClient;
    admin = context.payer;

    recipient = anchor.web3.Keypair.generate();
    feeRecipient = anchor.web3.Keypair.generate();

    const setupResult = await startSetupBankrun(program, admin, banksClient, context, recipient, feeRecipient);
    mintAddressA = setupResult.mintAddressA;
    mintAddressB = setupResult.mintAddressB;
    globalConfig = findGlobalConfigPDA(program.programId)[0];
  });


  it("Deposit", async () => {
    const depositAmount = 100000;
    const depositFee = new anchor.BN(calculateDepositFee(depositAmount));
    
    await createAtaBankrun(banksClient, admin, feeRecipient.publicKey, mintAddressA);

    const depositExtData: ExtData = {
      recipient: getAssociatedTokenAddressSync(mintAddressA, globalConfig, true),
      extAmount: new anchor.BN(depositAmount),
      encryptedOutput: Buffer.from("12"),
      fee: depositFee,
      feeRecipient: getAssociatedTokenAddressSync(mintAddressA, feeRecipient.publicKey, true),
      mintAddressA: mintAddressA,
      mintAddressB: mintAddressA,
    };
    
    const depositInputs = [
      new Utxo({ lightWasm, mintAddress: mintAddressA.toString() }),
      new Utxo({ lightWasm, mintAddress: mintAddressA.toString() }) 
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
    const depositExtDataHash = getExtDataHash(depositExtData);
    const depositExtDataHashFieldElement = hashToFieldElement(depositExtDataHash);

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

    const depositTx = await buildDepositInstruction(program, depositProofToSubmit, depositExtData, admin.publicKey, mintAddressA);
    await sendBankrunTransaction(
      banksClient,
      depositTx,
      admin,
      [],
      1000000
    );
    
    for (const commitment of depositOutputCommitments) {
      globalMerkleTree.insert(commitment);
    }

    depositedUtxo = depositOutputs[0];
  });

  it("Withdraw", async () => {

    const withdrawalAmount = 50000;
    const withdrawalFee = new anchor.BN(calculateWithdrawalFee(withdrawalAmount));

    await createAtaBankrun(banksClient, admin, recipient.publicKey, mintAddressA);
    await createAtaBankrun(banksClient, admin, feeRecipient.publicKey, mintAddressA);
    
    const withdrawExtData: ExtData = {
      recipient: recipient.publicKey,
      extAmount: new anchor.BN(-withdrawalAmount),
      encryptedOutput: Buffer.from(""),
      fee: withdrawalFee,
      feeRecipient: getAssociatedTokenAddressSync(mintAddressA, feeRecipient.publicKey, true),
      mintAddressA: mintAddressA,
      mintAddressB: mintAddressA,
    };

    const withdrawInputs = [
      depositedUtxo,
      new Utxo({ lightWasm, mintAddress: mintAddressA.toString() }),
    ];

    const inputsSum = withdrawInputs.reduce((sum, x) => sum.add(x.amount), new anchor.BN(0));
    const publicAmount0 = new anchor.BN(-withdrawalAmount).sub(withdrawalFee).add(FIELD_SIZE).mod(FIELD_SIZE);
    const remainingAmount = inputsSum.sub(new anchor.BN(withdrawalAmount)).sub(withdrawalFee);

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
      if (input.amount.gt(new anchor.BN(0))) {
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

    const withdrawTx = await buildWithdrawInstruction(program, withdrawProofToSubmit, withdrawExtData, admin.publicKey, mintAddressA);
    await sendBankrunTransaction(
      banksClient,
      withdrawTx,
      admin,
      [],
      1000000
    );

    for (const commitment of withdrawOutputCommitments) {
      globalMerkleTree.insert(commitment);
    }

    withdrawOutputUtxo = withdrawOutputs[0];
    console.log("Withdraw successful, remaining UTXO:", withdrawOutputUtxo.amount.toString());
  });

  // it("Deposit with existing UTXO (top-up)", async () => {
  //   const topUpAmount = 30000;
  //   const topUpFee = new anchor.BN(calculateDepositFee(topUpAmount));

   
  //   const topUpExtData: ExtData = {
  //     recipient: getAssociatedTokenAddressSync(mintAddressA, globalConfig, true),
  //     extAmount: new anchor.BN(topUpAmount),
  //     encryptedOutput: Buffer.from(""),
  //     fee: topUpFee,
  //     feeRecipient: feeRecipient.publicKey,
  //     mintAddressA: mintAddressA,
  //     mintAddressB: mintAddressA,
  //   };

  //   const topUpInputs = [
  //     withdrawOutputUtxo,
  //     new Utxo({ lightWasm, mintAddress: mintAddressA.toString() })
  //   ];

  //   const inputsSum = topUpInputs.reduce((sum, x) => sum.add(x.amount), new anchor.BN(0));
  //   const publicAmount = new anchor.BN(topUpAmount).sub(topUpFee);
  //   const publicAmountNumber = publicAmount.add(FIELD_SIZE).mod(FIELD_SIZE);
  //   const totalOutputAmount = inputsSum.add(publicAmount);

  //   const topUpOutputs = [
  //     new Utxo({
  //       lightWasm,
  //       amount: totalOutputAmount.toString(),
  //       index: globalMerkleTree._layers[0].length,
  //       mintAddress: mintAddressA.toString()
  //     }),
  //     new Utxo({
  //       lightWasm,
  //       amount: 0,
  //       mintAddress: mintAddressA.toString()
  //     })
  //   ];

  //   const topUpInputMerklePathIndices = [];
  //   const topUpInputMerklePathElements = [];

  //   for (let i = 0; i < topUpInputs.length; i++) {
  //     const input = topUpInputs[i];
  //     if (input.amount.gt(new anchor.BN(0))) {
  //       const commitment = await input.getCommitment();
  //       input.index = globalMerkleTree.indexOf(commitment);
  //       if (input.index === -1) {
  //         throw new Error(`UTXO commitment not found in tree: ${commitment}`);
  //       }
  //       topUpInputMerklePathIndices.push(input.index);
  //       topUpInputMerklePathElements.push(globalMerkleTree.path(input.index).pathElements);
  //     } else {
  //       topUpInputMerklePathIndices.push(0);
  //       topUpInputMerklePathElements.push(new Array(globalMerkleTree.levels).fill(0));
  //     }
  //   }

  //   const topUpInputNullifiers = await Promise.all(topUpInputs.map(x => x.getNullifier()));
  //   const topUpOutputCommitments = await Promise.all(topUpOutputs.map(x => x.getCommitment()));
  //   const topUpRoot = globalMerkleTree.root();
  //   const topUpExtDataHash = getExtDataHash(topUpExtData);

  //   const topUpInput: ProofInput = {
  //     root: topUpRoot,
  //     inputNullifier: topUpInputNullifiers,
  //     outputCommitment: topUpOutputCommitments,
  //     publicAmount0: publicAmountNumber.toString(),
  //     publicAmount1: "0",
  //     extDataHash: topUpExtDataHash,
  //     mintAddress0: publicKeyToFieldElement(mintAddressA),
  //     mintAddress1: publicKeyToFieldElement(mintAddressA),
  //     inAmount: topUpInputs.map(x => x.amount.toString(10)),
  //     inMintAddress: topUpInputs.map(x => x.mintAddress),
  //     inPrivateKey: topUpInputs.map(x => x.keypair.privkey),
  //     inBlinding: topUpInputs.map(x => x.blinding.toString(10)),
  //     inPathIndices: topUpInputMerklePathIndices,
  //     inPathElements: topUpInputMerklePathElements,
  //     outAmount: topUpOutputs.map(x => x.amount.toString(10)),
  //     outMintAddress: topUpOutputs.map(x => x.mintAddress),
  //     outPubkey: topUpOutputs.map(x => x.keypair.pubkey),
  //     outBlinding: topUpOutputs.map(x => x.blinding.toString(10)),
  //   };

  //   const topUpProofResult = await prove(topUpInput, keyBasePath);
  //   const topUpProofInBytes = parseProofToBytesArray(topUpProofResult.proof, true);
  //   const topUpInputsInBytes = parseToBytesArray(topUpProofResult.publicSignals);

  //   const compressedProof = negateAndCompressProof({
  //     a: new Uint8Array(topUpProofInBytes.proofA),
  //     b: new Uint8Array(topUpProofInBytes.proofB.flat()),
  //     c: new Uint8Array(topUpProofInBytes.proofC),
  //   });

  //   const topUpProofToSubmit: ProofToSubmit = {
  //     proofA: compressedProof.a,
  //     proofB: compressedProof.b,
  //     proofC: compressedProof.c,
  //     root: topUpInputsInBytes[0],
  //     publicAmount0: topUpInputsInBytes[1],
  //     publicAmount1: topUpInputsInBytes[2],
  //     extDataHash: topUpInputsInBytes[3],
  //     inputNullifiers: [topUpInputsInBytes[6], topUpInputsInBytes[7]],
  //     outputCommitments: [topUpInputsInBytes[8], topUpInputsInBytes[9]],
  //   };

  //   const topUpTx = await buildDepositInstruction(program, topUpProofToSubmit, topUpExtData, admin.publicKey, mintAddressA);
  //   await sendBankrunTransaction(
  //     banksClient,
  //     topUpTx,
  //     admin,
  //     [],
  //     1000000
  //   );

  //   for (const commitment of topUpOutputCommitments) {
  //     globalMerkleTree.insert(commitment);
  //   }

  //   withdrawOutputUtxo = topUpOutputs[0];
  //   console.log("Top-up successful! New balance:", totalOutputAmount.toString());
  // });

  // it("Deposit mintB for swap", async () => {
  //   const depositAmount = 100000;
  //   const depositFee = new anchor.BN(calculateDepositFee(depositAmount));
    
  //   await createAtaBankrun(banksClient, admin, feeRecipient.publicKey, mintAddressB);

  //   const depositExtData: ExtData = {
  //     recipient: getAssociatedTokenAddressSync(mintAddressB, globalConfig, true),
  //     extAmount: new anchor.BN(depositAmount),
  //     encryptedOutput: Buffer.from("deposit_mintB"),
  //     fee: depositFee,
  //     feeRecipient: getAssociatedTokenAddressSync(mintAddressB, feeRecipient.publicKey, true),
  //     mintAddressA: mintAddressB,
  //     mintAddressB: mintAddressB,
  //   };
    
  //   const depositInputs = [
  //     new Utxo({ lightWasm, mintAddress: mintAddressB.toString() }),
  //     new Utxo({ lightWasm, mintAddress: mintAddressB.toString() }) 
  //   ];

  //   const publicAmount = depositExtData.extAmount.sub(depositFee);
  //   const publicAmountNumber = publicAmount.add(FIELD_SIZE).mod(FIELD_SIZE);

  //   const depositOutputs = [
  //     new Utxo({
  //       lightWasm,
  //       amount: publicAmountNumber.toString(),
  //       index: globalMerkleTree._layers[0].length,
  //       mintAddress: mintAddressB.toString()
  //     }),
  //     new Utxo({
  //       lightWasm,
  //       amount: 0,
  //       mintAddress: mintAddressB.toString()
  //     })
  //   ];

  //   const depositInputMerklePathIndices = depositInputs.map(() => 0);
  //   const depositInputMerklePathElements = depositInputs.map(() => {
  //     return [...new Array(globalMerkleTree.levels).fill(0)];
  //   });
  //   const depositInputNullifiers = await Promise.all(depositInputs.map(x => x.getNullifier()));
  //   const depositOutputCommitments = await Promise.all(depositOutputs.map(x => x.getCommitment()));
  //   const depositRoot = globalMerkleTree.root();
  //   const depositExtDataHash = getExtDataHash(depositExtData);

  //   const depositInput: ProofInput = {
  //     root: depositRoot,
  //     inputNullifier: depositInputNullifiers,
  //     outputCommitment: depositOutputCommitments,
  //     publicAmount0: publicAmountNumber.toString(),
  //     publicAmount1: "0",
  //     extDataHash: depositExtDataHash,
  //     mintAddress0: publicKeyToFieldElement(mintAddressB),
  //     mintAddress1: publicKeyToFieldElement(mintAddressB),
  //     inAmount: depositInputs.map(x => x.amount.toString(10)),
  //     inMintAddress: depositInputs.map(x => x.mintAddress),
  //     inPrivateKey: depositInputs.map(x => x.keypair.privkey),
  //     inBlinding: depositInputs.map(x => x.blinding.toString(10)),
  //     inPathIndices: depositInputMerklePathIndices,
  //     inPathElements: depositInputMerklePathElements,
  //     outAmount: depositOutputs.map(x => x.amount.toString(10)),
  //     outMintAddress: depositOutputs.map(x => x.mintAddress),
  //     outPubkey: depositOutputs.map(x => x.keypair.pubkey),
  //     outBlinding: depositOutputs.map(x => x.blinding.toString(10)),
  //   };

  //   const depositProofResult = await prove(depositInput, keyBasePath);
  //   const depositProofInBytes = parseProofToBytesArray(depositProofResult.proof, true);
  //   const depositInputsInBytes = parseToBytesArray(depositProofResult.publicSignals);

  //   const compressedProof = negateAndCompressProof({
  //     a: new Uint8Array(depositProofInBytes.proofA),
  //     b: new Uint8Array(depositProofInBytes.proofB.flat()),
  //     c: new Uint8Array(depositProofInBytes.proofC),
  //   });

  //   const depositProofToSubmit: ProofToSubmit = {
  //     proofA: compressedProof.a,
  //     proofB: compressedProof.b,
  //     proofC: compressedProof.c,
  //     root: depositInputsInBytes[0],
  //     publicAmount0: depositInputsInBytes[1],
  //     publicAmount1: depositInputsInBytes[2],
  //     extDataHash: depositInputsInBytes[3],
  //     inputNullifiers: [depositInputsInBytes[6], depositInputsInBytes[7]],
  //     outputCommitments: [depositInputsInBytes[8], depositInputsInBytes[9]],
  //   };

  //   const depositTx = await buildDepositInstruction(program, depositProofToSubmit, depositExtData, admin.publicKey, mintAddressB);
  //   await sendBankrunTransaction(
  //     banksClient,
  //     depositTx,
  //     admin,
  //     [],
  //     1000000
  //   );
    
  //   for (const commitment of depositOutputCommitments) {
  //     globalMerkleTree.insert(commitment);
  //   }

  //   depositedUtxoMintB = depositOutputs[0];
  //   console.log("Deposit mintB successful, UTXO amount:", depositedUtxoMintB.amount.toString());
  // });

  // it("Swap mintA to mintB", async () => {
  //   await transferTokenBankrun(banksClient, admin, globalConfig, mintAddressB, 100000);
    
  //   const targetUtxoMintA = withdrawOutputUtxo;
  //   const swapAmountIn = 20000;
  //   const swapMinAmountOut = 10000;
  //   const swapFee = new anchor.BN(0);

  //   const reserveTokenAccountOutput = getAssociatedTokenAddressSync(
  //     mintAddressB,
  //     globalConfig,
  //     true
  //   );

  //   const swapExtData: SwapData = {
  //     recipient: reserveTokenAccountOutput,
  //     extAmount: new anchor.BN(-swapAmountIn),
  //     extMinAmountOut: new anchor.BN(swapMinAmountOut),
  //     encryptedOutput: Buffer.from("swapOutput"),
  //     fee: swapFee,
  //     feeRecipient: feeRecipient.publicKey,
  //     mintAddressA: mintAddressA,
  //     mintAddressB: mintAddressB,
  //   };

  //   const swapInputs = [
  //     targetUtxoMintA,
  //     new Utxo({ lightWasm, mintAddress: mintAddressB.toString() })
  //   ];

  //   const inputsSum = swapInputs.reduce((sum, x) => sum.add(x.amount), new anchor.BN(0));
  //   const publicAmount0 = new anchor.BN(-swapAmountIn).sub(swapFee).add(FIELD_SIZE).mod(FIELD_SIZE);
  //   const publicAmount1 = new anchor.BN(swapMinAmountOut).add(FIELD_SIZE).mod(FIELD_SIZE);
  //   const remainingAmountMintA = inputsSum.sub(new anchor.BN(swapAmountIn)).sub(swapFee);
  //   const swappedAmountMintB = new anchor.BN(swapMinAmountOut);

  //   const swapOutputs = [
  //     new Utxo({
  //       lightWasm,
  //       amount: remainingAmountMintA.toString(),
  //       index: globalMerkleTree._layers[0].length,
  //       mintAddress: mintAddressA.toString()
  //     }),
  //     new Utxo({
  //       lightWasm,
  //       amount: swappedAmountMintB.toString(),
  //       index: globalMerkleTree._layers[0].length + 1,
  //       mintAddress: mintAddressB.toString()
  //     })
  //   ];

  //   const swapInputMerklePathIndices = [];
  //   const swapInputMerklePathElements = [];

  //   for (let i = 0; i < swapInputs.length; i++) {
  //     const input = swapInputs[i];
  //     if (input.amount.gt(new anchor.BN(0))) {
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

  //   const swapProofResult = await prove(swapInput, keyBasePath);
  //   const swapProofInBytes = parseProofToBytesArray(swapProofResult.proof, true);
  //   const swapInputsInBytes = parseToBytesArray(swapProofResult.publicSignals);

  //   const compressedProof = negateAndCompressProof({
  //     a: new Uint8Array(swapProofInBytes.proofA),
  //     b: new Uint8Array(swapProofInBytes.proofB.flat()),
  //     c: new Uint8Array(swapProofInBytes.proofC),
  //   });

  //   const swapProofToSubmit: ProofToSubmit = {
  //     proofA: compressedProof.a,
  //     proofB: compressedProof.b,
  //     proofC: compressedProof.c,
  //     root: swapInputsInBytes[0],
  //     publicAmount0: swapInputsInBytes[1],
  //     publicAmount1: swapInputsInBytes[2],
  //     extDataHash: swapInputsInBytes[3],
  //     inputNullifiers: [swapInputsInBytes[6], swapInputsInBytes[7]],
  //     outputCommitments: [swapInputsInBytes[8], swapInputsInBytes[9]],
  //   };

  //   const swapTx = await buildSwapInstruction(program, swapProofToSubmit, swapExtData, admin.publicKey, mintAddressA, mintAddressB);
  //   await sendBankrunTransaction(
  //     banksClient,
  //     swapTx,
  //     admin,
  //     [],
  //     1400000
  //   );

  //   for (const commitment of swapOutputCommitments) {
  //     globalMerkleTree.insert(commitment);
  //   }

  //   console.log("Swap successful - swapped mintA to mintB");
  // });

});

