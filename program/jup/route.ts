import { VersionedTransaction } from '@solana/web3.js';
import { Buffer } from 'buffer';
export async function getOrderResponse(inputMint: string, outputMint: string, amount: string, taker: string) {
    const quoteResponse = await (
        await fetch(
            'https://lite-api.jup.ag/swap/v1/quote?inputMint=So11111111111111111111111111111111111111112&outputMint=EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v&amount=100000000&slippageBps=50&restrictIntermediateTokens=true'
        )
    ).json();

    console.log(JSON.stringify(quoteResponse, null, 2));

    const swapResponse = await (
        await fetch('https://lite-api.jup.ag/swap/v1/swap', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                quoteResponse,
                userPublicKey: taker,

                // ADDITIONAL PARAMETERS TO OPTIMIZE FOR TRANSACTION LANDING
                // See next guide to optimize for transaction landing
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

    console.log(JSON.stringify(swapResponse, null, 2));
    const transactionBase64 = swapResponse.swapTransaction
    const transaction = VersionedTransaction.deserialize(Buffer.from(transactionBase64, 'base64'));
    console.log(JSON.stringify(transaction, null, 2));
    return quoteResponse;
}

getOrderResponse('So11111111111111111111111111111111111111112', 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v', '100000000', '78Z82f93Xb8VhsQfmiHB6WsFzMDy4zbDKzCis8h5pFZK');