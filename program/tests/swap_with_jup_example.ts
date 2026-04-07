// import * as anchor from "@coral-xyz/anchor";
// import { Program } from "@coral-xyz/anchor";
// import { Yona } from "../target/types/yona";
// import { PublicKey, Keypair } from "@solana/web3.js";
// import { buildSwapWithJupiter } from "./jup";

// /**
//  * Build swap instruction with Jupiter integration
//  * Returns instruction array that can be used with sendTransactionWithALT
//  */
// export async function buildSwapWithJupiterInstruction(
//     program: Program<Yona>,
//     proof: any,
//     extDataMinified: any,
//     encryptedOutput1: Buffer,
//     encryptedOutput2: Buffer,
//     inputMint: PublicKey,
//     outputMint: PublicKey,
//     swapAmount: string,
//     userPublicKey: PublicKey,
//     slippageBps: number = 50
// ): Promise<{ instructions: any[], remainingAccounts: any[], jupiterProgramId: PublicKey }> {
//     // Step 1: Get Jupiter swap data and remaining accounts
//     const { jupiterSwapData, remainingAccounts, jupiterProgramId } = await buildSwapWithJupiter(
//         new PublicKey("So11111111111111111111111111111111111111112"),
//         new PublicKey("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"),
//         "100000000",
//         new PublicKey("78Z82f93Xb8VhsQfmiHB6WsFzMDy4zbDKzCis8h5pFZK"),
//         slippageBps
//     );
//     console.log("Jupiter swap data:", Buffer.from(jupiterSwapData).toString('base64'));
//     console.log("Jupiter swap data length:", jupiterSwapData.length);
//     console.log("Remaining accounts count:", remainingAccounts.length);
//     console.log("Jupiter program ID:", jupiterProgramId.toBase58());

//     // Step 2: Find PDAs
//     const [treeAccount] = PublicKey.findProgramAddressSync(
//         [Buffer.from("merkle_tree")],
//         program.programId
//     );

//     const [globalConfig] = PublicKey.findProgramAddressSync(
//         [Buffer.from("global_config")],
//         program.programId
//     );

//     const [nullifier0] = PublicKey.findProgramAddressSync(
//         [Buffer.from("nullifier0"), Buffer.from(proof.inputNullifiers[0])],
//         program.programId
//     );

//     const [nullifier1] = PublicKey.findProgramAddressSync(
//         [Buffer.from("nullifier1"), Buffer.from(proof.inputNullifiers[1])],
//         program.programId
//     );


//     // Step 3: Get token accounts
//     const reserveTokenAccountInput = await anchor.utils.token.associatedAddress({
//         mint: inputMint,
//         owner: globalConfig,
//     });

//     const reserveTokenAccountOutput = await anchor.utils.token.associatedAddress({
//         mint: outputMint,
//         owner: globalConfig,
//     });

//     const jupiterMockAccountInput = await anchor.utils.token.associatedAddress({
//         mint: inputMint,
//         owner: userPublicKey,
//     });

//     const jupiterMockAccountOutput = await anchor.utils.token.associatedAddress({
//         mint: outputMint,
//         owner: userPublicKey,
//     });

//     // Get fee recipient from extDataMinified (assuming it's there)
//     const feeRecipientAccount = extDataMinified.feeRecipient || userPublicKey;

//     // Step 4: Build instruction
//     console.log("Building swap instruction with Jupiter CPI...");

//     const instruction = await program.methods
//         .swap(
//             proof,
//             extDataMinified,
//             encryptedOutput1,
//             encryptedOutput2,
//             Buffer.from(jupiterSwapData) // Pass the Jupiter instruction data as Buffer
//         )
//         .accountsStrict({
//             treeAccount,
//             nullifier0,
//             nullifier1,
//             nullifier2,
//             nullifier3,
//             globalConfig,
//             inputMint,
//             outputMint,
//             reserveTokenAccountInput,
//             reserveTokenAccountOutput,
//             feeRecipientAccount,
//             jupiterMockAccountInput,
//             jupiterMockAccountOutput,
//             jupiterProgram: jupiterProgramId,
//             user: userPublicKey,
//             systemProgram: anchor.web3.SystemProgram.programId,
//             tokenProgram: anchor.utils.token.TOKEN_PROGRAM_ID,
//         })
//         .remainingAccounts(remainingAccounts)
//         .instruction();

//     return {
//         instructions: [instruction],
//         remainingAccounts,
//         jupiterProgramId
//     };
// }

// /**
//  * Example of how to call the swap instruction with Jupiter integration
//  * 
//  * This is a demonstration of how to:
//  * 1. Get Jupiter swap data
//  * 2. Pass it as instruction data
//  * 3. Pass Jupiter accounts as remaining accounts
//  */
// export async function exampleSwapWithJupiter(
//     program: Program<Yona>,
//     provider: anchor.AnchorProvider,
//     proof: any,
//     extDataMinified: any,
//     encryptedOutput1: Buffer,
//     encryptedOutput2: Buffer,
//     inputMint: PublicKey,
//     outputMint: PublicKey,
//     swapAmount: string,
//     user: Keypair
// ) {
//     const { instructions, remainingAccounts, jupiterProgramId } = await buildSwapWithJupiterInstruction(
//         program,
//         proof,
//         extDataMinified,
//         encryptedOutput1,
//         encryptedOutput2,
//         inputMint,
//         outputMint,
//         swapAmount,
//         user.publicKey,
//         50 // 0.5% slippage
//     );

//     console.log("Sending transaction with", instructions.length, "instructions");

//     const tx = new anchor.web3.Transaction();
//     instructions.forEach(ix => tx.add(ix));

//     const signature = await provider.sendAndConfirm(tx, [user]);
//     console.log("Swap transaction signature:", signature);
//     return signature;
// }

// /**
//  * Example of calling swap WITHOUT Jupiter (original behavior)
//  */
// export async function exampleSwapWithoutJupiter(
//     program: Program<Yona>,
//     provider: anchor.AnchorProvider,
//     proof: any,
//     extDataMinified: any,
//     encryptedOutput1: Buffer,
//     encryptedOutput2: Buffer,
//     inputMint: PublicKey,
//     outputMint: PublicKey,
//     user: Keypair
// ) {
//     // Step 1: Find PDAs (same as above)
//     const [treeAccount] = PublicKey.findProgramAddressSync(
//         [Buffer.from("merkle_tree")],
//         program.programId
//     );

//     const [globalConfig] = PublicKey.findProgramAddressSync(
//         [Buffer.from("global_config")],
//         program.programId
//     );

//     const [nullifier0] = PublicKey.findProgramAddressSync(
//         [Buffer.from("nullifier0"), Buffer.from(proof.inputNullifiers[0])],
//         program.programId
//     );

//     const [nullifier1] = PublicKey.findProgramAddressSync(
//         [Buffer.from("nullifier1"), Buffer.from(proof.inputNullifiers[1])],
//         program.programId
//     );



//     // Step 2: Get token accounts
//     const reserveTokenAccountInput = await anchor.utils.token.associatedAddress({
//         mint: inputMint,
//         owner: globalConfig,
//     });

//     const reserveTokenAccountOutput = await anchor.utils.token.associatedAddress({
//         mint: outputMint,
//         owner: globalConfig,
//     });

//     const jupiterMockAccountInput = await anchor.utils.token.associatedAddress({
//         mint: inputMint,
//         owner: user.publicKey,
//     });

//     const jupiterMockAccountOutput = await anchor.utils.token.associatedAddress({
//         mint: outputMint,
//         owner: user.publicKey,
//     });

//     const feeRecipientAccount = new PublicKey("FEE_RECIPIENT_PUBKEY_HERE");

//     // Step 3: Build and send transaction WITHOUT Jupiter
//     console.log("Building swap transaction without Jupiter...");

//     const jupiterProgramId = new PublicKey("JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4");

//     const tx = await program.methods
//         .swap(
//             proof,
//             extDataMinified,
//             encryptedOutput1,
//             encryptedOutput2,
//             null // No Jupiter data
//         )
//         .accountsStrict({
//             treeAccount,
//             nullifier0,
//             nullifier1,
//             nullifier2,
//             nullifier3,
//             globalConfig,
//             inputMint,
//             outputMint,
//             reserveTokenAccountInput,
//             reserveTokenAccountOutput,
//             feeRecipientAccount,
//             jupiterMockAccountInput,
//             jupiterMockAccountOutput,
//             jupiterProgram: jupiterProgramId, // Still need to provide the account
//             user: user.publicKey,
//             systemProgram: anchor.web3.SystemProgram.programId,
//             tokenProgram: anchor.utils.token.TOKEN_PROGRAM_ID,
//         })
//         // No remaining accounts needed
//         .signers([user])
//         .rpc();

//     console.log("Swap transaction signature:", tx);
//     return tx;
// }

