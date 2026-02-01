import * as anchor from "@coral-xyz/anchor";
import { utils } from "ffjavascript";
import BN from 'bn.js';
import { Utxo } from './utxo';
import * as borsh from 'borsh';
import { sha256 } from '@ethersproject/sha2';
import { Connection, AccountInfo, PublicKey } from '@solana/web3.js';
import { ProgramTestContext } from "solana-bankrun";
import { ACCOUNT_SIZE, AccountLayout, getAssociatedTokenAddressSync, TOKEN_PROGRAM_ID } from "@solana/spl-token";

/**
 * Converts an anchor.BN to a byte array of length 32 (big-endian format)
 * @param bn - The anchor.BN to convert
 * @returns A number array representing the bytes
 */
export function bnToBytes(bn: anchor.BN): number[] {
  // Cast the result to number[] since we know the output is a byte array
  return Array.from(
    utils.leInt2Buff(utils.unstringifyBigInts(bn.toString()), 32)
  ).reverse() as number[];
}

// BN254 field size for ZK circuits
const FIELD_SIZE = BigInt('21888242871839275222246405745257275088548364400416034343698204186575808495617');

/**
 * Converts a Solana PublicKey to a numeric string representation for circuit inputs
 * Converts all 32 bytes to BigInt and takes modulo FIELD_SIZE to fit in BN254 field
 * @param publicKey - The Solana PublicKey (base58 encoded string or PublicKey object)
 * @returns A decimal string representation that fits in BN254 field
 */
export function publicKeyToFieldElement(publicKey: string | PublicKey): string {
  const pk = typeof publicKey === 'string' ? new PublicKey(publicKey) : publicKey;
  const bytes = pk.toBytes();
  
  // Convert all 32 bytes to BigInt (big-endian)
  let value = BigInt(0);
  for (let i = 0; i < bytes.length; i++) {
    value = (value << BigInt(8)) | BigInt(bytes[i]);
  }
  // Take modulo to ensure it fits in BN254 field

  return (value % FIELD_SIZE).toString();
}

/**
 * Converts a hash (Uint8Array) to a field element string for circuit inputs
 * SHA256 returns bytes in big-endian order, we need to convert to decimal string
 * @param hash - The hash as Uint8Array (32 bytes)
 * @returns A decimal string representation that fits in BN254 field
 */
export function hashToFieldElement(hash: Uint8Array): string {
  // Convert all 32 bytes to BigInt (big-endian - same as publicKeyToFieldElement)
  let value = BigInt(0);
  for (let i = 0; i < hash.length; i++) {
    value = (value << BigInt(8)) | BigInt(hash[i]);
  }
  // Take modulo to ensure it fits in BN254 field
  return (value % FIELD_SIZE).toString();
}

/**
 * Mock encryption function - in real implementation this would be proper encryption
 * For testing, we just return a fixed prefix to ensure consistent extDataHash
 * @param value Value to encrypt
 * @returns Encrypted string representation
 */
export function mockEncrypt(value: Utxo): string {
  return JSON.stringify(value);

}

/**
 * Calculates the hash of ext data using Borsh serialization
 * @param extData External data object containing recipient, amount, encrypted outputs, fee, fee recipient, and mint address
 * @returns The hash as a Uint8Array (32 bytes)
 */
export function getExtDataHash(extData: {
  recipient: string | PublicKey;
  extAmount: string | number | BN;
  encryptedOutput: string | Uint8Array; // Optional for Account Data Separation
  fee: string | number | BN;
  feeRecipient: string | PublicKey;
  mintAddressA: string | PublicKey;
  mintAddressB: string | PublicKey;
}): Uint8Array {
  // Convert all inputs to their appropriate types
  const recipient =
    extData.recipient instanceof PublicKey
      ? extData.recipient
      : new PublicKey(extData.recipient);

  const feeRecipient =
    extData.feeRecipient instanceof PublicKey
      ? extData.feeRecipient
      : new PublicKey(extData.feeRecipient);

  const mintAddressA =
    extData.mintAddressA instanceof PublicKey
      ? extData.mintAddressA
      : new PublicKey(extData.mintAddressA);
  const mintAddressB =
    extData.mintAddressB instanceof PublicKey
      ? extData.mintAddressB
      : new PublicKey(extData.mintAddressB);
  // Convert to BN for proper i64/u64 handling
  const extAmount = new BN(extData.extAmount.toString());
  const fee = new BN(extData.fee.toString());

  // Handle encrypted outputs - they might not be present in Account Data Separation approach
  const encryptedOutput = extData.encryptedOutput
    ? Buffer.from(extData.encryptedOutput as any)
    : Buffer.alloc(0); // Empty buffer if not provided

  // Define the borsh schema matching the Rust struct
  const schema = {
    struct: {
      recipient: { array: { type: "u8", len: 32 } },
      extAmount: "i64",
      encryptedOutput: { array: { type: "u8" } },
      fee: "u64",
      feeRecipient: { array: { type: "u8", len: 32 } },
      mintAddressA: { array: { type: "u8", len: 32 } },
      mintAddressB: { array: { type: "u8", len: 32 } },
    },
  };

  const value = {
    recipient: recipient.toBytes(),
    extAmount: extAmount, // BN instance - Borsh handles it correctly with i64 type
    encryptedOutput: encryptedOutput,
    fee: fee, // BN instance - Borsh handles it correctly with u64 type
    feeRecipient: feeRecipient.toBytes(),
    mintAddressA: mintAddressA.toBytes(),
    mintAddressB: mintAddressB.toBytes(),
  };
  console.log("value: ", value);
  // Serialize with Borsh
  const serializedData = borsh.serialize(schema, value);
  // Calculate the SHA-256 hash
  const hashHex = sha256(serializedData);
  // Convert from hex string to Uint8Array
  return Buffer.from(hashHex.slice(2), "hex");
}

/**
 * Calculates the hash of ext data using Borsh serialization
 * @param extData External data object containing recipient, amount, encrypted outputs, fee, fee recipient, and mint address
 * @returns The hash as a Uint8Array (32 bytes)
 */
export function getSwapExtDataHash(extData: {
  extAmount: string | number | BN;
  extMinAmountOut: string | number | BN;
  encryptedOutput?: string | Uint8Array;  // Optional for Account Data Separation
  fee: string | number | BN;
  feeRecipient: string | PublicKey;
  mintAddressA: string | PublicKey;
  mintAddressB: string | PublicKey;
}): Uint8Array {

  // Convert all inputs to their appropriate types
  const feeRecipient = extData.feeRecipient instanceof PublicKey
    ? extData.feeRecipient
    : new PublicKey(extData.feeRecipient);

  const mintAddressA = extData.mintAddressA instanceof PublicKey
    ? extData.mintAddressA
    : new PublicKey(extData.mintAddressA);
  const mintAddressB = extData.mintAddressB instanceof PublicKey
    ? extData.mintAddressB
    : new PublicKey(extData.mintAddressB);
  // Convert to BN for proper i64/u64 handling
  const extAmount = new BN(extData.extAmount.toString());
  const extMinAmountOut = new BN(extData.extMinAmountOut.toString());
  const fee = new BN(extData.fee.toString());

  // Handle encrypted output - it might not be present in Account Data Separation approach
  const encryptedOutput = extData.encryptedOutput
    ? Buffer.from(extData.encryptedOutput as any)
    : Buffer.alloc(0); // Empty buffer if not provided

  // Define the borsh schema matching the Rust struct
  const schema = {
    struct: {
      extAmount: 'i64',
      extMinAmountOut: 'i64',
      encryptedOutput: { array: { type: 'u8' } },
      fee: 'u64',
      feeRecipient: { array: { type: 'u8', len: 32 } },
      mintAddressA: { array: { type: 'u8', len: 32 } },
      mintAddressB: { array: { type: 'u8', len: 32 } },
    }
  };

  const value = {
    extAmount: extAmount,  // BN instance - Borsh handles it correctly with i64 type
    extMinAmountOut: extMinAmountOut,  // BN instance - Borsh handles it correctly with i64 type
    encryptedOutput: encryptedOutput,
    fee: fee,  // BN instance - Borsh handles it correctly with u64 type
    feeRecipient: feeRecipient.toBytes(),
    mintAddressA: mintAddressA.toBytes(),
    mintAddressB: mintAddressB.toBytes(),
  };
  console.log("value: ", value);
  // Serialize with Borsh
  const serializedData = borsh.serialize(schema, value);
  // Calculate the SHA-256 hash
  const hashHex = sha256(serializedData);
  // Convert from hex string to Uint8Array
  return Buffer.from(hashHex.slice(2), 'hex');
} 


export async function setupATA(
  context: ProgramTestContext,
  mint: PublicKey,
  owner: PublicKey,
  amount: number  
): Promise<PublicKey> {
  const tokenAccData = Buffer.alloc(ACCOUNT_SIZE);
  AccountLayout.encode(
    {
      mint: mint,
      owner,
      amount: BigInt(amount),
      delegateOption: 0,
      delegate: PublicKey.default,
      delegatedAmount: BigInt(0),
      state: 1,
      isNativeOption: 0,
      isNative: BigInt(0),
      closeAuthorityOption: 0,
      closeAuthority: PublicKey.default,
    },
    tokenAccData,
  );

  const ata = getAssociatedTokenAddressSync(mint, owner, true);
  const ataAccountInfo = {
    lamports: 1_000_000_000,
    data: tokenAccData,
    owner: TOKEN_PROGRAM_ID,
    executable: false,
  };

  context.setAccount(ata, ataAccountInfo);
  return ata;
}



export async function copyAccountsData(connection: Connection, ...accounts: PublicKey[]) {
  const data: { address: PublicKey; info: AccountInfo<Buffer> }[] = [];
  const toCopy = [
    ...accounts,
  ];
  for (const key of toCopy) {
    const accountInfo = await connection.getAccountInfo(new PublicKey(key));
    if (accountInfo) {
      data.push({
        address: new PublicKey(key),
        info: accountInfo,
      });
    }
  }
  return data;
}


