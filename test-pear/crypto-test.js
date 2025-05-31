import crypto from "crypto";
import { x25519 } from '@noble/curves/ed25519';
import { sha256 } from '@noble/hashes/sha256';
import { concatBytes } from '@noble/hashes/utils';
import { pbkdf2 } from '@noble/hashes/pbkdf2';
import { hmac } from '@noble/hashes/hmac';

class ImprovedSPAKE2 {
  constructor() {
    const seedM = '8f40c5adb68f25624ae5b214ea767a6ec94d829d3d7b5e1ad1ba6f3e2138285f';
    const seedN = 'd8bbd68ea4f0b5a2e59031b9cf9af4f4ebea47e98d4bf407062b2f2e5f2d3a99';

    // Generate curve points from the hexadecimal seeds
    this.M = ed25519.decodePoint(seedM, 'hex');
    this.N = ed25519.decodePoint(seedN, 'hex');
  }

  generateKeyPair() {
    const privateKey = x25519.utils.randomPrivateKey();
    const publicKey = x25519.getPublicKey(privateKey);
    return { privateKey, publicKey };
  }

  hashPassword(password) {
    const salt = crypto.randomBytes(16);
    const key = pbkdf2(sha256, password, salt, { c: 10000, dkLen: 32 });
    return { key, salt };
  }

  computeX(isAlice, privateKey, passwordHash) {
    const point = isAlice ? this.M : this.N;
    const xPrivate = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
      xPrivate[i] = privateKey[i] ^ passwordHash[i];
    }
    const X = x25519.getPublicKey(xPrivate);
    return { xPrivate, X };
  }

  computeSharedSecret(xPrivate, Y) {
    return x25519.getSharedSecret(xPrivate, Y);
  }

  deriveSessionKey(isAlice, X, Y, sharedSecret) {
    const info = concatBytes(
      new TextEncoder().encode("SPAKE2 Key Derivation"),
      isAlice ? X : Y,
      isAlice ? Y : X
    );
    return hmac(sha256, sharedSecret, info);
  }

  generateConfirmation(sessionKey) {
    return hmac(sha256, sessionKey, new TextEncoder().encode("Confirmation"));
  }

  verifyConfirmation(sessionKey, confirmation) {
    const expected = this.generateConfirmation(sessionKey);
    return crypto.timingSafeEqual(expected, confirmation);
  }

  bytesToHex(bytes) {
    return Buffer.from(bytes).toString('hex');
  }
}

async function runSPAKE2() {
  const spake2 = new ImprovedSPAKE2();
  const password = "correct horse battery staple";
  const { key: passwordHash, salt } = spake2.hashPassword(password);

  console.log('Password Hash:', spake2.bytesToHex(passwordHash));
  console.log('Salt:', spake2.bytesToHex(salt));

  const alice = spake2.generateKeyPair();
  const bob = spake2.generateKeyPair();

  const aliceResult = spake2.computeX(true, alice.privateKey, passwordHash);
  const bobResult = spake2.computeX(false, bob.privateKey, passwordHash);

  const aliceSharedSecret = spake2.computeSharedSecret(aliceResult.xPrivate, bobResult.X);
  const bobSharedSecret = spake2.computeSharedSecret(bobResult.xPrivate, aliceResult.X);

  const aliceSessionKey = spake2.deriveSessionKey(true, aliceResult.X, bobResult.X, aliceSharedSecret);
  const bobSessionKey = spake2.deriveSessionKey(false, bobResult.X, aliceResult.X, bobSharedSecret);

  console.log('Alice session key:', spake2.bytesToHex(aliceSessionKey));
  console.log('Bob session key:', spake2.bytesToHex(bobSessionKey));

  // Key confirmation
  const aliceConfirmation = spake2.generateConfirmation(aliceSessionKey);
  const bobConfirmation = spake2.generateConfirmation(bobSessionKey);

  console.log('Alice confirms Bob:', spake2.verifyConfirmation(aliceSessionKey, bobConfirmation));
  console.log('Bob confirms Alice:', spake2.verifyConfirmation(bobSessionKey, aliceConfirmation));
}

runSPAKE2().catch(console.error);