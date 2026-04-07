import { expect } from "chai";
import { ctr } from "@noble/ciphers/aes.js";
import { hmac } from "@noble/hashes/hmac.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { randomBytes } from "@noble/hashes/utils.js";
import { x25519 } from "@noble/curves/ed25519";
import BN from "bn.js";
import { Buffer } from "buffer";

/**
 * Standalone encryption helpers mirroring frontend EncryptionService.
 * Tests the transfer encryption flow: sender encrypts, recipient decrypts via ECIES.
 */

function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

function encryptSymmetric(data: Uint8Array, encryptionKey: Uint8Array): Uint8Array {
  const iv = randomBytes(16);
  const key = encryptionKey.slice(0, 16);
  const encryptedData = ctr(key, iv).encrypt(data);
  const hmacKey = encryptionKey.slice(16, 31);
  const h = hmac.create(sha256, hmacKey);
  h.update(iv);
  h.update(encryptedData);
  const authTag = h.digest().slice(0, 16);
  const combined = new Uint8Array(iv.length + authTag.length + encryptedData.length);
  combined.set(iv, 0);
  combined.set(authTag, iv.length);
  combined.set(encryptedData, iv.length + authTag.length);
  return combined;
}

function decryptSymmetric(encryptedData: Uint8Array, encryptionKey: Uint8Array): Uint8Array {
  const iv = encryptedData.slice(0, 16);
  const authTag = encryptedData.slice(16, 32);
  const data = encryptedData.slice(32);
  const hmacKey = encryptionKey.slice(16, 31);
  const h = hmac.create(sha256, hmacKey);
  h.update(iv);
  h.update(data);
  const calculatedTag = h.digest().slice(0, 16);
  if (!timingSafeEqual(authTag, calculatedTag)) {
    throw new Error("HMAC mismatch");
  }
  const key = encryptionKey.slice(0, 16);
  return ctr(key, iv).decrypt(data);
}

function deriveX25519Keypair(encryptionKey: Uint8Array): { publicKey: Uint8Array; privateKey: Uint8Array } {
  const privateKey = sha256(Buffer.concat([encryptionKey, Buffer.from("x25519-derive")]));
  const publicKey = x25519.getPublicKey(privateKey);
  return { publicKey, privateKey };
}

function serializeUtxoData(amount: number, blinding: number, index: number, mintPrefix: number): Buffer {
  const amountBytes = new BN(amount).toArrayLike(Buffer, "le", 8);
  const blindingBytes = new BN(blinding).toArrayLike(Buffer, "le", 4);
  const indexBytes = new BN(index).toArrayLike(Buffer, "le", 4);
  const mintBytes = new BN(mintPrefix).toArrayLike(Buffer, "le", 4);
  return Buffer.concat([amountBytes, blindingBytes, indexBytes, mintBytes]);
}

/**
 * Encrypt for transfer: recipient ECIES + admin ECIES (no sender symmetric)
 * Format: [recipientEphPub(32b)] [recipient(72b)] [adminEphPub(32b)] [admin(72b)] = 208 bytes
 */
function encryptForTransfer(
  serializedUtxos: Uint8Array,
  recipientX25519Pub: Uint8Array,
  adminX25519Pub: Uint8Array,
): Uint8Array {
  // Recipient encryption (ECIES)
  const recipientEphPriv = x25519.utils.randomPrivateKey();
  const recipientEphPub = x25519.getPublicKey(recipientEphPriv);
  const recipientShared = x25519.getSharedSecret(recipientEphPriv, recipientX25519Pub);
  const recipientKey = sha256(recipientShared).slice(0, 31);
  const recipientEncrypted = encryptSymmetric(serializedUtxos, recipientKey);

  // Admin encryption (ECIES)
  const adminEphPriv = x25519.utils.randomPrivateKey();
  const adminEphPub = x25519.getPublicKey(adminEphPriv);
  const adminShared = x25519.getSharedSecret(adminEphPriv, adminX25519Pub);
  const adminKey = sha256(adminShared).slice(0, 31);
  const adminEncrypted = encryptSymmetric(serializedUtxos, adminKey);

  // Combine: recipientEphPub(32) | recipient(72) | adminEphPub(32) | admin(72) = 208
  const combined = new Uint8Array(32 + 72 + 32 + 72);
  let offset = 0;
  combined.set(recipientEphPub, offset); offset += 32;
  combined.set(recipientEncrypted, offset); offset += 72;
  combined.set(adminEphPub, offset); offset += 32;
  combined.set(adminEncrypted, offset);
  return combined;
}

/**
 * Decrypt recipient portion (ECIES) — starts at offset 0 in 208-byte format
 */
function decryptRecipientPortion(
  encryptedOutput: Uint8Array,
  recipientX25519Priv: Uint8Array,
): Uint8Array {
  const recipientEphPub = encryptedOutput.slice(0, 32);
  const recipientEncrypted = encryptedOutput.slice(32, 32 + 72);

  const sharedSecret = x25519.getSharedSecret(recipientX25519Priv, recipientEphPub);
  const recipientKey = sha256(sharedSecret).slice(0, 31);
  return decryptSymmetric(recipientEncrypted, recipientKey);
}

/**
 * Decrypt admin portion (ECIES) — starts at offset 104 in 208-byte format
 */
function decryptAdminPortion(
  encryptedOutput: Uint8Array,
  adminX25519Priv: Uint8Array,
): Uint8Array {
  const adminEphPub = encryptedOutput.slice(104, 104 + 32);
  const adminEncrypted = encryptedOutput.slice(104 + 32);

  const sharedSecret = x25519.getSharedSecret(adminX25519Priv, adminEphPub);
  const adminKey = sha256(sharedSecret).slice(0, 31);
  return decryptSymmetric(adminEncrypted, adminKey);
}

describe("Transfer Encryption", () => {
  // Simulate three parties: sender, recipient, admin
  const senderSignature = randomBytes(64);
  const recipientSignature = randomBytes(64);
  const adminSignature = randomBytes(64);

  const senderEncryptionKey = senderSignature.slice(0, 31);
  const recipientEncryptionKey = recipientSignature.slice(0, 31);
  const adminEncryptionKey = adminSignature.slice(0, 31);

  const senderX25519 = deriveX25519Keypair(senderEncryptionKey);
  const recipientX25519 = deriveX25519Keypair(recipientEncryptionKey);
  const adminX25519 = deriveX25519Keypair(adminEncryptionKey);

  // Two UTXOs: [recipient UTXO (50000)] + [sender change UTXO (30000)]
  const utxo1 = serializeUtxoData(50000, 12345, 10, 999);
  const utxo2 = serializeUtxoData(30000, 67890, 11, 999);
  const serializedUtxos = Buffer.concat([utxo1, utxo2]);

  it("encryptForTransfer produces 208 bytes", () => {
    const encrypted = encryptForTransfer(
      serializedUtxos,
      recipientX25519.publicKey,
      adminX25519.publicKey,
    );
    expect(encrypted.length).to.equal(208);
  });

  it("recipient can decrypt recipient portion (ECIES)", () => {
    const encrypted = encryptForTransfer(
      serializedUtxos,
      recipientX25519.publicKey,
      adminX25519.publicKey,
    );
    const decrypted = decryptRecipientPortion(encrypted, recipientX25519.privateKey);
    expect(Buffer.from(decrypted)).to.deep.equal(serializedUtxos);
  });

  it("admin can decrypt admin portion (ECIES)", () => {
    const encrypted = encryptForTransfer(
      serializedUtxos,
      recipientX25519.publicKey,
      adminX25519.publicKey,
    );
    const decrypted = decryptAdminPortion(encrypted, adminX25519.privateKey);
    expect(Buffer.from(decrypted)).to.deep.equal(serializedUtxos);
  });

  it("sender CANNOT decrypt recipient ECIES portion", () => {
    const encrypted = encryptForTransfer(
      serializedUtxos,
      recipientX25519.publicKey,
      adminX25519.publicKey,
    );
    expect(() => decryptRecipientPortion(encrypted, senderX25519.privateKey)).to.throw();
  });

  it("sender CANNOT decrypt admin ECIES portion", () => {
    const encrypted = encryptForTransfer(
      serializedUtxos,
      recipientX25519.publicKey,
      adminX25519.publicKey,
    );
    expect(() => decryptAdminPortion(encrypted, senderX25519.privateKey)).to.throw();
  });

  it("random third party cannot decrypt any portion", () => {
    const encrypted = encryptForTransfer(
      serializedUtxos,
      recipientX25519.publicKey,
      adminX25519.publicKey,
    );
    const thirdPartyX25519 = deriveX25519Keypair(randomBytes(31));

    expect(() => decryptRecipientPortion(encrypted, thirdPartyX25519.privateKey)).to.throw();
    expect(() => decryptAdminPortion(encrypted, thirdPartyX25519.privateKey)).to.throw();
  });

  it("deserialized UTXO data matches original after round-trip", () => {
    const encrypted = encryptForTransfer(
      serializedUtxos,
      recipientX25519.publicKey,
      adminX25519.publicKey,
    );

    const decrypted = decryptRecipientPortion(encrypted, recipientX25519.privateKey);

    // Parse first UTXO (20 bytes)
    const amount1 = new BN(decrypted.slice(0, 8), "le").toNumber();
    const blinding1 = new BN(decrypted.slice(8, 12), "le").toNumber();
    const index1 = new BN(decrypted.slice(12, 16), "le").toNumber();
    const mint1 = new BN(decrypted.slice(16, 20), "le").toNumber();

    expect(amount1).to.equal(50000);
    expect(blinding1).to.equal(12345);
    expect(index1).to.equal(10);
    expect(mint1).to.equal(999);

    // Parse second UTXO (20 bytes)
    const amount2 = new BN(decrypted.slice(20, 28), "le").toNumber();
    const blinding2 = new BN(decrypted.slice(28, 32), "le").toNumber();
    const index2 = new BN(decrypted.slice(32, 36), "le").toNumber();
    const mint2 = new BN(decrypted.slice(36, 40), "le").toNumber();

    expect(amount2).to.equal(30000);
    expect(blinding2).to.equal(67890);
    expect(index2).to.equal(11);
    expect(mint2).to.equal(999);
  });

  it("stealth address format: utxoPubkey:x25519PubHex", () => {
    // Simulate stealth address generation
    const utxoPubkey = "16092280401511638934750038518901322528188786491680877579116665348929495863150";
    const x25519PubHex = Buffer.from(recipientX25519.publicKey).toString("hex");

    const stealthAddress = `${utxoPubkey}:${x25519PubHex}`;

    // Parse it back
    const parts = stealthAddress.split(":");
    expect(parts.length).to.equal(2);

    const parsedUtxoPubkey = new BN(parts[0]);
    expect(parsedUtxoPubkey.toString()).to.equal(utxoPubkey);

    const parsedX25519Pub = Uint8Array.from(Buffer.from(parts[1], "hex"));
    expect(parsedX25519Pub.length).to.equal(32);
    expect(Buffer.from(parsedX25519Pub)).to.deep.equal(Buffer.from(recipientX25519.publicKey));
  });

  it("X25519 keypair derivation is deterministic", () => {
    const kp1 = deriveX25519Keypair(recipientEncryptionKey);
    const kp2 = deriveX25519Keypair(recipientEncryptionKey);
    expect(Buffer.from(kp1.publicKey)).to.deep.equal(Buffer.from(kp2.publicKey));
    expect(Buffer.from(kp1.privateKey)).to.deep.equal(Buffer.from(kp2.privateKey));
  });

  it("different signatures produce different X25519 keypairs", () => {
    expect(Buffer.from(senderX25519.publicKey)).to.not.deep.equal(
      Buffer.from(recipientX25519.publicKey),
    );
  });
});
