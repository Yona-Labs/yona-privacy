import { VersionedTransaction, PublicKey, TransactionInstruction, AddressLookupTableAccount } from '@solana/web3.js';
import { Buffer } from 'buffer';

/**
 * Fetch Jupiter quote and swap transaction
 */
export async function getJupiterSwapData(
    inputMint: string, 
    outputMint: string, 
    amount: string, 
    userPublicKey: string,
    slippageBps: number = 50
) {
    // Get quote from Jupiter
    const quoteResponse = await (
        await fetch(
            `https://lite-api.jup.ag/swap/v1/quote?inputMint=${inputMint}&outputMint=${outputMint}&amount=${amount}&slippageBps=${slippageBps}&restrictIntermediateTokens=true&`
        )
    ).json();

    console.log("Jupiter Quote Response:", JSON.stringify(quoteResponse, null, 2));

    // Get swap transaction from Jupiter
    const swapResponse = await (
        await fetch('https://lite-api.jup.ag/swap/v1/swap', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                quoteResponse,
                userPublicKey,
                dynamicComputeUnitLimit: true,
                dynamicSlippage: true,
                prioritizationFeeLamports: {
                    priorityLevelWithMaxLamports: {
                        maxLamports: 1000000,
                        priorityLevel: "veryHigh"
                    }
                }
            })
        })
    ).json();

    console.log("Jupiter Swap Response:", JSON.stringify(swapResponse, null, 2));
    
    const transactionBase64 = swapResponse.swapTransaction;
    const transaction = VersionedTransaction.deserialize(Buffer.from(transactionBase64, 'base64'));
    
    return {
        quoteResponse,
        swapResponse,
        transaction
    };
}

/**
 * Extract accounts and instruction data from Jupiter transaction
 * to be used with remaining_accounts and instruction data
 */
export function extractJupiterSwapInfo(transaction: VersionedTransaction) {
    if (transaction.message.compiledInstructions.length === 0) {
        throw new Error("No instructions found in transaction");
    }

    // Find Jupiter instruction (should be one of the main instructions)
    // Typically the Jupiter route instruction
    const jupiterProgramId = new PublicKey("JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4");
    
    // Get all account keys from the message (both static and from lookup tables)
    const staticAccountKeys = transaction.message.staticAccountKeys;
    
    console.log("Static account keys count:", staticAccountKeys.length);
    console.log("Address table lookups:", transaction.message.addressTableLookups?.length || 0);
    
    // Find Jupiter instruction
    let jupiterInstruction = null;
    let jupiterInstructionIndex = -1;
    
    for (let i = 0; i < transaction.message.compiledInstructions.length; i++) {
        const instruction = transaction.message.compiledInstructions[i];
        const programId = staticAccountKeys[instruction.programIdIndex];
        
        if (programId && programId.equals(jupiterProgramId)) {
            jupiterInstruction = instruction;
            jupiterInstructionIndex = i;
            break;
        }
    }
    
    if (!jupiterInstruction) {
        throw new Error("Jupiter instruction not found in transaction");
    }
    
    console.log(`Found Jupiter instruction at index ${jupiterInstructionIndex}`);
    console.log("Jupiter instruction data length:", jupiterInstruction.data.length);
    console.log("Jupiter instruction accounts count:", jupiterInstruction.accountKeyIndexes.length);
    
    // Extract accounts for Jupiter instruction
    // Filter out any undefined accounts (from lookup tables we don't have)
    const jupiterAccounts = jupiterInstruction.accountKeyIndexes
        .map(index => {
            if (index < staticAccountKeys.length) {
                return staticAccountKeys[index];
            }
            // Account is in lookup table, we can't resolve it without the table
            console.warn(`Account index ${index} exceeds static keys (${staticAccountKeys.length}), skipping`);
            return null;
        })
        .filter((key): key is PublicKey => key !== null);
    
    console.log("Resolved Jupiter accounts:", jupiterAccounts.length);
    
    // Extract instruction data
    const instructionData = Buffer.from(jupiterInstruction.data);
    
    return {
        jupiterProgramId,
        jupiterAccounts,
        instructionData: Array.from(instructionData),
        accountKeys: jupiterAccounts,
    };
}

/**
 * Build the swap instruction with Jupiter CPI
 */
export async function buildSwapWithJupiter(
    inputMint: PublicKey,
    outputMint: PublicKey,
    amount: string,
    userPublicKey: PublicKey,
    slippageBps: number = 50
) {
    // Get Jupiter swap data
    const { transaction } = await getJupiterSwapData(
        inputMint.toBase58(),
        outputMint.toBase58(),
        amount,
        userPublicKey.toBase58(),
        slippageBps
    );
    console.log("transaction:", transaction);
    // Extract accounts and instruction data
    const jupiterSwapInfo = extractJupiterSwapInfo(transaction);
    
    return {
        jupiterSwapData: jupiterSwapInfo.instructionData,
        remainingAccounts: jupiterSwapInfo.jupiterAccounts.map(pubkey => ({
            pubkey,
            isSigner: false,
            isWritable: true, // Conservative approach - mark all as writable
        })),
        jupiterProgramId: jupiterSwapInfo.jupiterProgramId,
    };
}

