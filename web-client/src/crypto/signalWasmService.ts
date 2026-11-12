/**
 * ============================================================================
 * ⚠️ CRITICAL SECURITY WARNING
 * ============================================================================
 * This library's bindings are NOT audited.
 * The upstream author explicitly states:
 * "The bindings themselves have not been audited and the project was
 * built with significant assistance from AI coding agents."
 *
 * For an anonymity-focused messenger (AnonChat):
 * DO NOT USE THIS IN PRODUCTION WITHOUT AN INDEPENDENT THIRD-PARTY CRYPTOGRAPHIC AUDIT.
 * USE STRICTLY FOR PROTOTYPING AND EXPERIMENTAL TESTING.
 * ============================================================================
 */

import init, { SignalClient } from '@getmaapp/signal-wasm';
import { EncryptedIndexedDb } from '../storage/encryptedIndexedDb';

export interface PreKeyBundleRegistration {
  uuid: string;
  deviceId: number;
  identityKey: any;
  signedPreKey: any;
  kyberPreKey: any;
  preKeys: any[];
}

export class SignalWasmService {
  private static instance: SignalWasmService | null = null;
  private client: SignalClient | null = null;
  private isWasmInitialized = false;
  private storage: EncryptedIndexedDb;

  private constructor() {
    this.storage = new EncryptedIndexedDb();
  }

  static getInstance(): SignalWasmService {
    if (!SignalWasmService.instance) {
      SignalWasmService.instance = new SignalWasmService();
    }
    return SignalWasmService.instance;
  }

  /**
   * Step 2: Initialize WebAssembly Engine and SignalClient.
   *
   * Note on Randomness:
   * WebAssembly in browsers does not have access to OS-level entropy (e.g. /dev/urandom).
   * Standard Rust `rand::rngs::OsRng` panics in browser environments.
   * @getmaapp/signal-wasm binds `window.crypto.getRandomValues` to satisfy CSPRNG requirements.
   */
  async initialize(uuid: string = 'anon-user-' + Math.random().toString(36).substring(7), deviceId: number = 1): Promise<void> {
    if (this.isWasmInitialized && this.client) {
      return;
    }

    // 1. Initialize Web Crypto backed storage
    await this.storage.init();

    // 2. Initialize the WebAssembly module
    await init();

    // 3. Instantiate client with user UUID and device ID
    this.client = new SignalClient(uuid, deviceId);
    this.isWasmInitialized = true;
  }

  getClient(): SignalClient {
    if (!this.client) {
      throw new Error('SignalClient is not initialized. Call initialize() first.');
    }
    return this.client;
  }

  /**
   * Step 3: Generate Keys for Registration
   * Generates identity key, signed prekey, Kyber PQ prekey, and 100 OPKs.
   */
  generateRegistrationKeys(): PreKeyBundleRegistration {
    const client = this.getClient();

    // 100 One-Time PreKeys
    const preKeys = client.generate_pre_keys(100);
    // Signed PreKey
    const signedPreKey = client.generate_signed_pre_key();
    // Post-Quantum Kyber PreKey
    const kyberPreKey = client.generate_kyber_pre_key();
    // Public Identity Key
    const identityKey = client.get_identity_public_key();

    return {
      uuid: 'self',
      deviceId: 1,
      identityKey,
      signedPreKey,
      kyberPreKey,
      preKeys,
    };
  }

  /**
   * Step 4: Session Establishment
   * Establishes a Double Ratchet session using recipient's public PreKeyBundle.
   */
  establishSession(recipientId: string, deviceId: number, preKeyBundle: any): void {
    const client = this.getClient();
    client.process_pre_key_bundle(recipientId, deviceId, preKeyBundle);
  }

  /**
   * Step 5: Encrypt Message
   */
  encryptMessage(recipientId: string, deviceId: number, plaintext: string): any {
    const client = this.getClient();
    return client.encrypt_message(recipientId, deviceId, plaintext);
  }

  /**
   * Step 5: Decrypt Received Message
   */
  decryptMessage(senderId: string, deviceId: number, ciphertext: any): string {
    const client = this.getClient();
    return client.decrypt_message(senderId, deviceId, ciphertext);
  }

  /**
   * Step 6: Safety Numbers (Built-in Verification)
   */
  generateSafetyNumber(recipientId: string, deviceId: number): string {
    const client = this.getClient();
    return client.generate_safety_number(recipientId, deviceId);
  }

  verifySafetyNumber(recipientId: string, deviceId: number, scannedNumber: string): boolean {
    const client = this.getClient();
    return client.verify_safety_number(recipientId, deviceId, scannedNumber);
  }

  /**
   * Step 7: Persistence (Encrypted IndexedDB)
   * Serializes active session and encrypts using Web Crypto AES-256-GCM before writing to IndexedDB.
   */
  async persistSession(recipientId: string, deviceId: number): Promise<void> {
    const client = this.getClient();
    // @getmaapp/signal-wasm export_session
    const serializedSession = (client as any).export_session(recipientId, deviceId);
    if (serializedSession) {
      await this.storage.saveEncryptedSession(recipientId, serializedSession);
    }
  }

  /**
   * Restores an exported session from encrypted IndexedDB.
   */
  async restoreSession(recipientId: string, deviceId: number): Promise<boolean> {
    const serialized = await this.storage.loadDecryptedSession(recipientId);
    if (!serialized) {
      return false;
    }
    const client = this.getClient();
    (client as any).import_session(recipientId, deviceId, serialized);
    return true;
  }
}

