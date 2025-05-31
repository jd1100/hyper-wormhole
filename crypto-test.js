import crypto from "crypto";
import { x25519 } from '@noble/curves/ed25519';
import { sha256 } from '@noble/hashes/sha256';
import { sha512 } from '@noble/hashes/sha512';
import { concatBytes } from '@noble/hashes/utils';
import { pbkdf2 } from '@noble/hashes/pbkdf2';
import * as utils from '@noble/curves/abstract/utils';

class ImprovedSPAKE2 {
  constructor() {
    // Generate constant points M and N. These are public parameters of the protocol.
    // They act as "blinding" factors to prevent offline dictionary attacks.
    this.M = this.generateConstantPoint("1.2.840.10045.3.1.7 point generation seed (M)");
    this.N = this.generateConstantPoint("1.2.840.10045.3.1.7 point generation seed (N)");
  }

  generateConstantPoint(seed) {
    // This method generates a point on the curve from a seed.
    // It's designed to be deterministic, so both Alice and Bob will generate the same M and N.
    const seedBuffer = new TextEncoder().encode(seed);
    for (let i = 1; i < 1000; i++) {
      const hash = sha512(concatBytes(seedBuffer, Uint8Array.from([i])));
      const pointCandidate = hash.slice(0, 32);
      // These bit manipulations ensure the generated point is on the curve
      pointCandidate[0] &= 248;
      pointCandidate[31] &= 127;
      pointCandidate[31] |= 64;
      try {
        return x25519.getPublicKey(pointCandidate);
      } catch (e) {
        // If the point is not valid, try the next one
      }
    }
    throw new Error("Failed to generate constant point");
  }

  generateKeyPair() {
    // Generate a new keypair for this session
    const privateKey = x25519.utils.randomPrivateKey();
    return { privateKey, publicKey: x25519.getPublicKey(privateKey) };
  }

  hashPassword(password) {
    // Hash the password using PBKDF2. This slows down potential brute-force attacks.
    const salt = crypto.randomBytes(16);
    const key = pbkdf2(sha256, password, salt, { c: 10000, dkLen: 32 });
    return { key, salt };
  }

  computeX(isAlice, privateKey, passwordHash) {
    // Compute the public value to be sent over the network
    const blind = isAlice ? this.M : this.N;
    // Combine the private key and password hash
    const scalar = this.scalarAdd(privateKey, passwordHash);
    // Compute the public value: g^scalar + blind
    const X = this.pointAdd(x25519.scalarMultBase(scalar), blind);
    return { scalar, X };
  }

  computeSharedSecret(scalar, Y, isAlice) {
    // Compute the shared secret from the other party's public value
    const blind = isAlice ? this.N : this.M;
    // Remove the blinding factor
    const unblindedY = this.pointSubtract(Y, blind);
    // Compute the shared secret
    return x25519.getSharedSecret(scalar, unblindedY);
  }

  // Helper function to add two scalars
  scalarAdd(a, b) {
    const result = new Uint8Array(32);
    let carry = 0;
    for (let i = 0; i < 32; i++) {
      carry += a[i] + b[i];
      result[i] = carry & 0xff;
      carry >>= 8;
    }
    return result;
  }

  // Helper function to add two points
  pointAdd(a, b) {
    return this.arrayXOR(a, b);
  }

  // Helper function to subtract two points
  pointSubtract(a, b) {
    return this.arrayXOR(a, b);
  }

  // Helper function to XOR two Uint8Arrays
  arrayXOR(a, b) {
    return a.map((byte, i) => byte ^ b[i]);
  }

  bytesToHex(bytes) {
    return utils.bytesToHex(bytes);
  }
}

async function runSPAKE2() {
  const spake2 = new ImprovedSPAKE2();
  
  // The shared password, in a real scenario this would be input by the user
  const password = "correct horse battery staple";
  
  // Hash the password. In a real scenario, Alice and Bob would do this independently
  const { key: passwordHash, salt } = spake2.hashPassword(password);

  console.log('Password Hash:', spake2.bytesToHex(passwordHash));
  console.log('Salt:', spake2.bytesToHex(salt));

  // Alice and Bob each generate their keypairs
  const alice = spake2.generateKeyPair();
  const bob = spake2.generateKeyPair();

  // Alice and Bob compute their public values
  const aliceResult = spake2.computeX(true, alice.privateKey, passwordHash);
  const bobResult = spake2.computeX(false, bob.privateKey, passwordHash);

  console.log('Alice X:', spake2.bytesToHex(aliceResult.X));
  console.log('Bob X:', spake2.bytesToHex(bobResult.X));

  // Alice and Bob exchange their public values (X) over the p2p channel

  // Alice and Bob compute the shared secret
  const aliceSharedSecret = spake2.computeSharedSecret(aliceResult.scalar, bobResult.X, true);
  const bobSharedSecret = spake2.computeSharedSecret(bobResult.scalar, aliceResult.X, false);

  console.log('Alice Shared Secret:', spake2.bytesToHex(aliceSharedSecret));
  console.log('Bob Shared Secret:', spake2.bytesToHex(bobSharedSecret));

  // Verify that Alice and Bob have computed the same shared secret
  const sharedSecretsMatch = crypto.timingSafeEqual(aliceSharedSecret, bobSharedSecret);
  console.log('Shared Secrets Match:', sharedSecretsMatch);
}

runSPAKE2().catch(console.error);