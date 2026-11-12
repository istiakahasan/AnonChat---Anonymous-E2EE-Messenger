/**
 * High-Entropy Recovery Code Implementation (Expo / React Native)
 *
 * Implements:
 * - Option B (Recommended): 24-word BIP39 mnemonic phrase (256-bit entropy + 8-bit SHA-256 checksum)
 * - Option A: Crockford Base32 52-character recovery code in 13 groups of 4 separated by spaces
 */

import { BIP39_ENGLISH_WORDLIST } from './bip39Words';

export const CROCKFORD_ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

/**
 * Generates 256 bits (32 bytes) of cryptographically secure random entropy.
 */
export function generateEntropy256(): Uint8Array {
  const entropy = new Uint8Array(32);
  crypto.getRandomValues(entropy);
  return entropy;
}

/**
 * Computes SHA-256 hash using Web Crypto API.
 */
async function sha256(data: Uint8Array): Promise<Uint8Array> {
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  return new Uint8Array(hashBuffer);
}

/**
 * Encodes 32-byte (256-bit) entropy into a 24-word BIP39 mnemonic phrase.
 */
export async function entropyToBip39(entropy: Uint8Array): Promise<string> {
  if (entropy.length !== 32) {
    throw new Error(`Invalid entropy length: expected 32 bytes, got ${entropy.length}`);
  }

  // 1. Calculate 8-bit checksum: first byte of SHA-256(entropy)
  const hash = await sha256(entropy);
  const checksum = hash[0];

  // 2. Build 264-bit stream
  const bits: number[] = [];
  for (let i = 0; i < entropy.length; i++) {
    const byte = entropy[i];
    for (let bitIdx = 7; bitIdx >= 0; bitIdx--) {
      bits.push((byte >> bitIdx) & 1);
    }
  }
  for (let bitIdx = 7; bitIdx >= 0; bitIdx--) {
    bits.push((checksum >> bitIdx) & 1);
  }

  // 3. Extract 24 chunks of 11 bits each
  const words: string[] = [];
  for (let i = 0; i < 24; i++) {
    let wordIdx = 0;
    for (let bitOffset = 0; bitOffset < 11; bitOffset++) {
      wordIdx = (wordIdx << 1) | bits[i * 11 + bitOffset];
    }
    words.push(BIP39_ENGLISH_WORDLIST[wordIdx]);
  }

  return words.join(' ');
}

/**
 * Decodes and validates a 24-word BIP39 mnemonic phrase, recovering 32-byte entropy.
 */
export async function bip39ToEntropy(phrase: string): Promise<Uint8Array> {
  const words = phrase.trim().toLowerCase().split(/\s+/);
  if (words.length !== 24) {
    throw new Error(`Invalid word count: expected 24 words, got ${words.length}`);
  }

  const bits: number[] = [];
  for (let i = 0; i < words.length; i++) {
    const word = words[i];
    const wordIdx = BIP39_ENGLISH_WORDLIST.indexOf(word);
    if (wordIdx === -1) {
      throw new Error(`Word not found in BIP39 wordlist: '${word}' at position ${i + 1}`);
    }
    for (let bitIdx = 10; bitIdx >= 0; bitIdx--) {
      bits.push((wordIdx >> bitIdx) & 1);
    }
  }

  // Extract 32-byte entropy
  const entropy = new Uint8Array(32);
  for (let byteIdx = 0; byteIdx < 32; byteIdx++) {
    let byte = 0;
    for (let bitOffset = 0; bitOffset < 8; bitOffset++) {
      byte = (byte << 1) | bits[byteIdx * 8 + bitOffset];
    }
    entropy[byteIdx] = byte;
  }

  // Extract 8-bit checksum
  let expectedChecksum = 0;
  for (let bitOffset = 0; bitOffset < 8; bitOffset++) {
    expectedChecksum = (expectedChecksum << 1) | bits[256 + bitOffset];
  }

  // Verify checksum
  const hash = await sha256(entropy);
  if (hash[0] !== expectedChecksum) {
    throw new Error('Invalid BIP39 checksum: phrase may be mistyped or corrupted');
  }

  return entropy;
}

/**
 * Generates a fresh 24-word BIP39 recovery code (Option B - Recommended).
 */
export async function generateBip39RecoveryCode(): Promise<string> {
  const entropy = generateEntropy256();
  return entropyToBip39(entropy);
}

/**
 * Encodes 32-byte (256-bit) entropy into Crockford Base32 (Option A: 52 characters in groups of 4).
 */
export function entropyToBase32(entropy: Uint8Array): string {
  if (entropy.length !== 32) {
    throw new Error(`Invalid entropy length: expected 32 bytes, got ${entropy.length}`);
  }

  const bits: number[] = [];
  for (let i = 0; i < entropy.length; i++) {
    const byte = entropy[i];
    for (let bitIdx = 7; bitIdx >= 0; bitIdx--) {
      bits.push((byte >> bitIdx) & 1);
    }
  }
  bits.push(0, 0, 0, 0); // 4 padding bits -> 260 bits

  const chars: string[] = [];
  for (let i = 0; i < 52; i++) {
    let val = 0;
    for (let bitOffset = 0; bitOffset < 5; bitOffset++) {
      val = (val << 1) | bits[i * 5 + bitOffset];
    }
    chars.push(CROCKFORD_ALPHABET[val]);
  }

  // Format in 13 groups of 4 separated by spaces
  const groups: string[] = [];
  for (let i = 0; i < 52; i += 4) {
    groups.push(chars.slice(i, i + 4).join(''));
  }
  return groups.join(' ');
}

/**
 * Decodes Crockford Base32 recovery code into 32-byte entropy.
 */
export function base32ToEntropy(code: string): Uint8Array {
  let normalized = code.replace(/[\s-]+/g, '').toUpperCase();
  normalized = normalized.replace(/O/g, '0').replace(/[IL]/g, '1');

  if (normalized.length !== 52) {
    throw new Error(`Invalid Base32 length: expected 52 characters, got ${normalized.length}`);
  }

  const bits: number[] = [];
  for (let i = 0; i < normalized.length; i++) {
    const c = normalized[i];
    const idx = CROCKFORD_ALPHABET.indexOf(c);
    if (idx === -1) {
      throw new Error(`Invalid Base32 character: '${c}'`);
    }
    for (let bitIdx = 4; bitIdx >= 0; bitIdx--) {
      bits.push((idx >> bitIdx) & 1);
    }
  }

  const entropy = new Uint8Array(32);
  for (let byteIdx = 0; byteIdx < 32; byteIdx++) {
    let byte = 0;
    for (let bitOffset = 0; bitOffset < 8; bitOffset++) {
      byte = (byte << 1) | bits[byteIdx * 8 + bitOffset];
    }
    entropy[byteIdx] = byte;
  }

  return entropy;
}

/**
 * Generates a fresh Crockford Base32 recovery code (Option A: 52 characters in 13 groups of 4).
 */
export function generateBase32RecoveryCode(): string {
  const entropy = generateEntropy256();
  return entropyToBase32(entropy);
}

/**
 * Validates any recovery code (BIP39 24 words or Base32 52 characters).
 */
export async function validateRecoveryCode(input: string): Promise<Uint8Array> {
  const trimmed = input.trim();
  const words = trimmed.split(/\s+/);

  if (words.length === 24) {
    return bip39ToEntropy(trimmed);
  }

  const stripped = trimmed.replace(/[\s-]+/g, '');
  if (stripped.length === 52) {
    return base32ToEntropy(trimmed);
  }

  throw new Error('Unrecognized recovery code format: must be 24 BIP39 words or 52 Base32 characters');
}

