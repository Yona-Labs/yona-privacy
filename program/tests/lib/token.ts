import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { BanksClient } from "solana-bankrun";
import {
    PublicKey,
    Keypair,
    SystemProgram,
    Transaction,
} from "@solana/web3.js";
import {
    TOKEN_PROGRAM_ID,
    createInitializeMint2Instruction,
    MINT_SIZE,
    createAssociatedTokenAccountInstruction,
    getAssociatedTokenAddressSync,
    createMintToInstruction
} from "@solana/spl-token";

/**
 * Setup protocol: create collateral mint and initialize config
 */
export async function createMint(params: {
    banksClient: BanksClient;
    payer: Keypair;
    admin: Keypair;
    lastBlockhash: string;
    decimals: number;
}): Promise<PublicKey> {
    const { banksClient, payer, admin, lastBlockhash, decimals } = params;

    // Create collateral mint
    const mintKeypair = Keypair.generate();
    const collateralMint = mintKeypair.publicKey;

    // Fixed rent-exempt lamports for mint account
    const MINT_RENT_LAMPORTS = 1461600;

    const createAccountIx = SystemProgram.createAccount({
        fromPubkey: payer.publicKey,
        newAccountPubkey: collateralMint,
        space: MINT_SIZE,
        lamports: MINT_RENT_LAMPORTS,
        programId: TOKEN_PROGRAM_ID,
    });

    const initMintIx = createInitializeMint2Instruction(
        collateralMint,
        decimals ?? 6, // decimals
        payer.publicKey, // mint authority
        null // freeze authority
    );

    const userTokenAccount = getAssociatedTokenAddressSync( 
        collateralMint,
        payer.publicKey,
        true
    );
    const createUserTokenAccountIx = createAssociatedTokenAccountInstruction(
        payer.publicKey,
        userTokenAccount,
        payer.publicKey,
        collateralMint
    );

    const mintToIx = createMintToInstruction(
        collateralMint,
        userTokenAccount,
        payer.publicKey,
        1000000000,
        [payer],
        TOKEN_PROGRAM_ID
    );
    const mintTx = new Transaction().add(createAccountIx, initMintIx, createUserTokenAccountIx, mintToIx  );
    mintTx.recentBlockhash = lastBlockhash;
    mintTx.sign(payer, mintKeypair);
    await banksClient.processTransaction(mintTx);

    console.log("Collateral Mint:", collateralMint.toBase58());

    // Verify mint account was created
    const mintAccount = await banksClient.getAccount(collateralMint);
    if (!mintAccount) {
        throw new Error("Failed to create collateral mint account");
    }

    // Initialize protocol config


    console.log("Protocol setup complete!");

    return collateralMint;
}



