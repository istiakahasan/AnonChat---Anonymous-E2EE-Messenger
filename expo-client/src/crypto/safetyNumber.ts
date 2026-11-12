/**
 * Signal Protocol 60-Digit Safety Number Derivation
 *
 * Algorithm (Signal Protocol Specification):
 * 1. For each user:
 *    - digest = SHA-512(identityKeyBytes || identifier)
 *    - Iterate SHA-512 5,200 times: digest = SHA-512(digest || identityKeyBytes)
 *    - Extract 6 groups of 5 digits (30 digits total) using 4-byte big-endian chunks % 100,000.
 * 2. Sort the two 30-digit fingerprints lexicographically (ensures Alice and Bob see identical numbers).
 * 3. Concatenate the two sorted fingerprints (60 digits total).
 * 4. Format as 12 groups of 5 digits separated by spaces.
 *
 * Verification State Storage (Local Only):
 * - Persisted in SecureStore (never uploaded to relay server):
 *   `contactId -> { safetyNumber, verifiedAt, lastRemoteKey }`
 * - When remote key changes, verifiedAt is reset to null and a warning is triggered.
 */

import * as SecureStore from 'expo-secure-store';

export const SIGNAL_FINGERPRINT_ITERATIONS = 5200;

export interface ContactVerificationRecord {
  contactId: string;
  safetyNumber: string;
  verifiedAt: number | null;
  lastRemoteKey: string;
}

export class SafetyNumberService {
  /**
   * Computes a SHA-512 digest using Web Crypto API.
   */
  private static async sha512(data: Uint8Array): Promise<Uint8Array> {
    const hashBuffer = await crypto.subtle.digest('SHA-512', data);
    return new Uint8Array(hashBuffer);
  }

  /**
   * Computes the 30-digit fingerprint for an individual party with 5,200 SHA-512 iterations.
   */
  static async computeIndividualFingerprint(
    identityKey: Uint8Array,
    identifier: string
  ): Promise<string> {
    const idBytes = new TextEncoder().encode(identifier);

    // Initial round: SHA-512(identityKey || identifier)
    const initialData = new Uint8Array(identityKey.length + idBytes.length);
    initialData.set(identityKey, 0);
    initialData.set(idBytes, identityKey.length);

    let digest = await this.sha512(initialData);

    // 5,200 iterations of SHA-512(digest || identityKey)
    for (let i = 0; i < SIGNAL_FINGERPRINT_ITERATIONS; i++) {
      const combined = new Uint8Array(digest.length + identityKey.length);
      combined.set(digest, 0);
      combined.set(identityKey, digest.length);
      digest = await this.sha512(combined);
    }

    // Extract 6 groups of 5 digits (30 digits total) from 4-byte big-endian chunks % 100,000
    const view = new DataView(digest.buffer, digest.byteOffset, digest.byteLength);
    let fingerprint = '';

    for (let i = 0; i < 6; i++) {
      const chunk = view.getUint32(i * 4, false); // Big-endian
      const fiveDigits = (chunk % 100000).toString().padStart(5, '0');
      fingerprint += fiveDigits;
    }

    return fingerprint;
  }

  /**
   * Derives the deterministic 60-digit composite Safety Number for two parties.
   *
   * Note:
   * Always call `generateCompositeSafetyNumber` for contact verification.
   * Never use single-key reference safety numbers for authentication.
   */
  static async generateCompositeSafetyNumber(
    localIdentityKey: Uint8Array,
    localIdentifier: string,
    remoteIdentityKey: Uint8Array,
    remoteIdentifier: string
  ): Promise<string> {
    const fpA = await this.computeIndividualFingerprint(localIdentityKey, localIdentifier);
    const fpB = await this.computeIndividualFingerprint(remoteIdentityKey, remoteIdentifier);

    // Lexicographical sort ensures Alice and Bob compute the exact same order
    const sorted = [fpA, fpB].sort();
    const combined = sorted[0] + sorted[1];

    // Format as 12 groups of 5 digits (60 digits total)
    const groups: string[] = [];
    for (let i = 0; i < 12; i++) {
      groups.push(combined.substring(i * 5, i * 5 + 5));
    }

    return groups.join(' ');
  }

  /**
   * Local Verification State Management in SecureStore.
   */
  private static getStorageKey(contactId: string): string {
    return `safety_verif_${contactId}`;
  }

  static async getVerificationState(contactId: string): Promise<ContactVerificationRecord | null> {
    const data = await SecureStore.getItemAsync(this.getStorageKey(contactId));
    return data ? JSON.parse(data) : null;
  }

  static async saveVerificationState(record: ContactVerificationRecord): Promise<void> {
    await SecureStore.setItemAsync(
      this.getStorageKey(record.contactId),
      JSON.stringify(record),
      { keychainAccessible: SecureStore.WHEN_UNLOCKED_THIS_DEVICE_ONLY }
    );
  }

  /**
   * Checks a contact's remote identity key on connect/message.
   * Returns { keyChanged: boolean, safetyNumber: string, isVerified: boolean }
   */
  static async processContactKey(
    localIdentityKey: Uint8Array,
    localId: string,
    contactId: string,
    remoteKeyBytes: Uint8Array
  ): Promise<{ keyChanged: boolean; safetyNumber: string; isVerified: boolean }> {
    const remoteKeyHex = Array.from(remoteKeyBytes).map(b => b.toString(16).padStart(2, '0')).join('');
    const currentSafetyNumber = await this.generateCompositeSafetyNumber(
      localIdentityKey,
      localId,
      remoteKeyBytes,
      contactId
    );

    const existing = await this.getVerificationState(contactId);

    if (!existing) {
      // First interaction: store record (unverified by default until user reviews)
      const record: ContactVerificationRecord = {
        contactId,
        safetyNumber: currentSafetyNumber,
        verifiedAt: null,
        lastRemoteKey: remoteKeyHex,
      };
      await this.saveVerificationState(record);
      return { keyChanged: false, safetyNumber: currentSafetyNumber, isVerified: false };
    }

    if (existing.lastRemoteKey !== remoteKeyHex) {
      // KEY CHANGED: Reset verification and warn!
      const updatedRecord: ContactVerificationRecord = {
        contactId,
        safetyNumber: currentSafetyNumber,
        verifiedAt: null, // Reset verification!
        lastRemoteKey: remoteKeyHex,
      };
      await this.saveVerificationState(updatedRecord);
      return { keyChanged: true, safetyNumber: currentSafetyNumber, isVerified: false };
    }

    return {
      keyChanged: false,
      safetyNumber: existing.safetyNumber,
      isVerified: existing.verifiedAt !== null,
    };
  }

  /**
   * Marks a contact as manually verified by user.
   */
  static async markContactVerified(contactId: string): Promise<void> {
    const state = await this.getVerificationState(contactId);
    if (state) {
      state.verifiedAt = Date.now();
      await this.saveVerificationState(state);
    }
  }
}

