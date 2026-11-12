/**
 * Key-Change Detection Engine (Safety Number Verification)
 *
 * SECURITY REQUIREMENT:
 * - If a contact's identity key changes, BLOCK sending and warn the user.
 * - Defends against Man-in-the-Middle (MitM) key injection and relay identity spoofing.
 */

import { SecureStorageService } from './secureStorage';
import { KeyChangeAlert } from '../types/signal';

export class KeyChangeDetector {
  /**
   * Computes a human-readable 60-digit or hex safety number fingerprint
   * from an identity public key.
   */
  static formatFingerprint(key: Uint8Array | string): string {
    const bytes = typeof key === 'string' ? new TextEncoder().encode(key) : key;
    let hex = '';
    for (let i = 0; i < bytes.length; i++) {
      hex += bytes[i].toString(16).padStart(2, '0');
    }
    // Format into 4-character chunks: "XXXX XXXX XXXX ..."
    const chunks = hex.match(/.{1,4}/g) || [];
    return chunks.slice(0, 8).join(' ').toUpperCase();
  }

  /**
   * Compares the contact's current public identity key with the securely stored key.
   *
   * @param contactName Recipient identifier (e.g. 'bob', 'user123')
   * @param currentIdentityKey The identity key received from the server bundle or message
   * @returns { verified: boolean, alert?: KeyChangeAlert }
   */
  static async checkContactKey(
    contactName: string,
    currentIdentityKey: Uint8Array | string
  ): Promise<{ verified: boolean; alert?: KeyChangeAlert }> {
    const currentFingerprint = this.formatFingerprint(currentIdentityKey);
    const knownKeys = await SecureStorageService.getContactIdentityKeysMap();
    const storedFingerprint = knownKeys[contactName];

    // Case 1: First time communicating with this contact -> Store and trust
    if (!storedFingerprint) {
      await SecureStorageService.saveContactIdentityKey(contactName, currentFingerprint);
      return { verified: true };
    }

    // Case 2: Key matches the trusted stored key -> Verified
    if (storedFingerprint === currentFingerprint) {
      return { verified: true };
    }

    // Case 3: CRITICAL KEY CHANGE DETECTED!
    // A previously trusted contact has a different identity key.
    // BLOCK communication until user manually verifies and approves the new safety number.
    const alert: KeyChangeAlert = {
      contactName,
      previousKeyFingerprint: storedFingerprint,
      newKeyFingerprint: currentFingerprint,
      detectedAt: Date.now(),
    };

    return {
      verified: false,
      alert,
    };
  }

  /**
   * Explicitly updates and trusts the new identity key for a contact
   * ONLY AFTER the user reviews the safety number warning.
   */
  static async approveKeyChange(
    contactName: string,
    newIdentityKey: Uint8Array | string
  ): Promise<void> {
    const newFingerprint = this.formatFingerprint(newIdentityKey);
    await SecureStorageService.saveContactIdentityKey(contactName, newFingerprint);
  }
}

