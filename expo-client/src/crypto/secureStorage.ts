/**
 * Secure Key Storage Module
 *
 * SECURITY REQUIREMENT:
 * - Store identityKeyPair.privateKey in expo-secure-store, NEVER in AsyncStorage.
 * - Private keys are encrypted using hardware-backed keystore/keychain (Secure Enclave / Android Keystore).
 * - Enforce WHEN_UNLOCKED_THIS_DEVICE_ONLY to prevent unencrypted cloud backup leakage.
 */

import * as SecureStore from 'expo-secure-store';

const SECURE_STORE_OPTIONS: SecureStore.SecureStoreOptions = {
  keychainAccessible: SecureStore.WHEN_UNLOCKED_THIS_DEVICE_ONLY,
};

const STORAGE_KEYS = {
  IDENTITY_PRIVATE_KEY: 'signal_identity_private_key',
  IDENTITY_PUBLIC_KEY: 'signal_identity_public_key',
  REGISTRATION_ID: 'signal_registration_id',
  SIGNED_PREKEY: 'signal_signed_prekey',
  ONE_TIME_PREKEYS: 'signal_one_time_prekeys',
  CONTACT_IDENTITY_KEYS: 'signal_contact_identity_keys_map',
} as const;

export class SecureStorageService {
  /**
   * Encodes a Uint8Array or string to a Base64 string for storage.
   */
  private static toBase64(value: Uint8Array | string): string {
    if (typeof value === 'string') {
      return value;
    }
    let binary = '';
    const bytes = new Uint8Array(value);
    const len = bytes.byteLength;
    for (let i = 0; i < len; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  }

  /**
   * Decodes a Base64 string back to Uint8Array.
   */
  private static fromBase64(b64: string): Uint8Array {
    const binary = atob(b64);
    const len = binary.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }

  /**
   * Saves the Identity KeyPair. Private key is strictly isolated in SecureStore.
   */
  static async saveIdentityKeyPair(
    privateKey: Uint8Array | string,
    publicKey: Uint8Array | string
  ): Promise<void> {
    const privB64 = this.toBase64(privateKey);
    const pubB64 = this.toBase64(publicKey);

    // CRITICAL: Private key stored in hardware-backed SecureStore
    await SecureStore.setItemAsync(
      STORAGE_KEYS.IDENTITY_PRIVATE_KEY,
      privB64,
      SECURE_STORE_OPTIONS
    );
    await SecureStore.setItemAsync(
      STORAGE_KEYS.IDENTITY_PUBLIC_KEY,
      pubB64,
      SECURE_STORE_OPTIONS
    );
  }

  /**
   * Loads the Identity KeyPair from SecureStore. Returns null if not yet generated.
   */
  static async loadIdentityKeyPair(): Promise<{
    privateKey: Uint8Array;
    publicKey: Uint8Array;
  } | null> {
    const privB64 = await SecureStore.getItemAsync(
      STORAGE_KEYS.IDENTITY_PRIVATE_KEY,
      SECURE_STORE_OPTIONS
    );
    const pubB64 = await SecureStore.getItemAsync(
      STORAGE_KEYS.IDENTITY_PUBLIC_KEY,
      SECURE_STORE_OPTIONS
    );

    if (!privB64 || !pubB64) {
      return null;
    }

    return {
      privateKey: this.fromBase64(privB64),
      publicKey: this.fromBase64(pubB64),
    };
  }

  /**
   * Saves the Registration ID.
   */
  static async saveRegistrationId(regId: number): Promise<void> {
    await SecureStore.setItemAsync(
      STORAGE_KEYS.REGISTRATION_ID,
      regId.toString(),
      SECURE_STORE_OPTIONS
    );
  }

  /**
   * Loads the Registration ID from SecureStore.
   */
  static async loadRegistrationId(): Promise<number | null> {
    const str = await SecureStore.getItemAsync(
      STORAGE_KEYS.REGISTRATION_ID,
      SECURE_STORE_OPTIONS
    );
    return str ? parseInt(str, 10) : null;
  }

  /**
   * Saves Signed PreKey metadata and private key in SecureStore.
   */
  static async saveSignedPreKey(signedPreKey: any): Promise<void> {
    const serialized = JSON.stringify({
      id: signedPreKey.id,
      publicKey: this.toBase64(signedPreKey.publicKey),
      privateKey: this.toBase64(signedPreKey.privateKey),
      signature: this.toBase64(signedPreKey.signature),
    });
    await SecureStore.setItemAsync(
      STORAGE_KEYS.SIGNED_PREKEY,
      serialized,
      SECURE_STORE_OPTIONS
    );
  }

  /**
   * Loads Signed PreKey from SecureStore.
   */
  static async loadSignedPreKey(): Promise<any | null> {
    const data = await SecureStore.getItemAsync(
      STORAGE_KEYS.SIGNED_PREKEY,
      SECURE_STORE_OPTIONS
    );
    if (!data) return null;
    const parsed = JSON.parse(data);
    return {
      id: parsed.id,
      publicKey: this.fromBase64(parsed.publicKey),
      privateKey: this.fromBase64(parsed.privateKey),
      signature: this.fromBase64(parsed.signature),
    };
  }

  /**
   * Stores known contact identity keys map for Key-Change detection.
   * Maps contactName -> identityKeyHex
   */
  static async getContactIdentityKeysMap(): Promise<Record<string, string>> {
    const data = await SecureStore.getItemAsync(
      STORAGE_KEYS.CONTACT_IDENTITY_KEYS,
      SECURE_STORE_OPTIONS
    );
    return data ? JSON.parse(data) : {};
  }

  static async saveContactIdentityKey(contactName: string, keyHex: string): Promise<void> {
    const map = await this.getContactIdentityKeysMap();
    map[contactName] = keyHex;
    await SecureStore.setItemAsync(
      STORAGE_KEYS.CONTACT_IDENTITY_KEYS,
      JSON.stringify(map),
      SECURE_STORE_OPTIONS
    );
  }

  /**
   * Wipes all keys (e.g. on account logout or self-destruct).
   */
  static async clearAllKeys(): Promise<void> {
    await SecureStore.deleteItemAsync(STORAGE_KEYS.IDENTITY_PRIVATE_KEY, SECURE_STORE_OPTIONS);
    await SecureStore.deleteItemAsync(STORAGE_KEYS.IDENTITY_PUBLIC_KEY, SECURE_STORE_OPTIONS);
    await SecureStore.deleteItemAsync(STORAGE_KEYS.REGISTRATION_ID, SECURE_STORE_OPTIONS);
    await SecureStore.deleteItemAsync(STORAGE_KEYS.SIGNED_PREKEY, SECURE_STORE_OPTIONS);
    await SecureStore.deleteItemAsync(STORAGE_KEYS.CONTACT_IDENTITY_KEYS, SECURE_STORE_OPTIONS);
  }
}

