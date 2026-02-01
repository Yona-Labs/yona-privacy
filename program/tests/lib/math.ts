import { BN  } from "@coral-xyz/anchor";
import { DEPOSIT_FEE_RATE, WITHDRAW_FEE_RATE } from "./constants";
import * as crypto from "crypto";
import { utils } from 'ffjavascript';

export function generateRandomNullifier(): Uint8Array {
    return crypto.randomBytes(32);
}

// Helper function to calculate fees based on amount and fee rate
export function calculateFee(amount: number, feeRate: number): number {
    return Math.floor((amount * feeRate) / 10000);
}

// Helper function to calculate deposit fee
export function calculateDepositFee(amount: number): number {
    return calculateFee(amount, DEPOSIT_FEE_RATE);
}

// Helper function to calculate withdrawal fee
export  function calculateWithdrawalFee(amount: number): number {
    return calculateFee(amount, WITHDRAW_FEE_RATE);
}

export function bnToBytes(bn: BN): number[] {
    // Cast the result to number[] since we know the output is a byte array
    return Array.from(
        utils.leInt2Buff(utils.unstringifyBigInts(bn.toString()), 32)
    ).reverse() as number[];
}       