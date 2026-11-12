/**
 * AnonChat Signal Protocol Service for Expo / React Native
 *
 * Implements @toled/signal-expo protocol lifecycle:
 * 1. Installation & Prebuild checks
 * 2. Identity Generation (One-time per device, private key locked in SecureStore)
 * 3. Protocol Initialization
 * 4. Public PreKeyBundle Export (ZERO private keys)
 * 5. Session Establishment with Recipient & Key-Change Detection
 * 6. Message Encryption (TextEncoder -> Uint8Array -> Ciphertext)
 * 7. Message Decryption (Ciphertext -> Uint8Array -> TextDecoder)
 */

import {
  generateIdentityKeyPair,
  generateRegistrationId,
  generatePreKeys,
  generateSignedPreKey,
  initialize,
  createSession,
  encrypt,
  decrypt,
} from '@toled/signal-expo';

import { SecureStorageService } from './secureStorage';
import { KeyChangeDetector } from './keyChangeDetector';
import { SignalAddress, ServerPublicBundle, KeyChangeAlert } from '../types/signal';

export class KeyChangeException extends Error {
  alert: KeyChangeAlert;
  constructor(alert: KeyChangeAlert) {
    super(`Identity key changed for contact '${alert.contactName}'! Sending blocked.`);
    this.name = 'KeyChangeException';
    this.alert = alert;
  }
}

export class SignalService {
  private static instance: SignalService | null = null;
  private isInitialized = false;

  private identityKeyPair: any = null;
  private registrationId: number = 0;
  private preKeys: any[] = [];
  private signedPreKey: any = null;

  private constructor() {}

  static getInstance(): SignalService {
    if (!SignalService.instance) {
      SignalService.instance = new SignalService();
    }
    return SignalService.instance;
  }

  /**
   * Step 2 & 3: Bootstrap and Initialize Protocol
   * Loads existing keys from SecureStore, or generates them on first device boot.
   */
  async ensureInitialized(): Promise<ServerPublicBundle> {
    if (this.isInitialized) {
      return this.exportPublicBundle();
    }

    // Try loading existing identity from SecureStore
    const storedIdentity = await SecureStorageService.loadIdentityKeyPair();
    const storedRegId = await SecureStorageService.loadRegistrationId();
    const storedSignedPreKey = await SecureStorageService.loadSignedPreKey();

    if (storedIdentity && storedRegId && storedSignedPreKey) {
      // Re-initialize using existing hardware-backed keys
      this.identityKeyPair = storedIdentity;
      this.registrationId = storedRegId;
      this.signedPreKey = storedSignedPreKey;
      // PreKeys pool
      this.preKeys = generatePreKeys(1, 100);
    } else {
      // Step 2: One-time identity generation per device
      this.identityKeyPair = generateIdentityKeyPair();
      this.registrationId = generateRegistrationId();
      this.preKeys = generatePreKeys(1, 100);
      this.signedPreKey = generateSignedPreKey(this.identityKeyPair, 1);

      // SECURITY: Save private key in expo-secure-store, NEVER in AsyncStorage!
      await SecureStorageService.saveIdentityKeyPair(
        this.identityKeyPair.privateKey,
        this.identityKeyPair.publicKey
      );
      await SecureStorageService.saveRegistrationId(this.registrationId);
      await SecureStorageService.saveSignedPreKey(this.signedPreKey);
    }

    // Step 3: Initialize protocol (Required before encrypt/decrypt)
    await initialize(
      this.identityKeyPair,
      this.registrationId,
      this.preKeys,
      this.signedPreKey
    );

    this.isInitialized = true;
    return this.exportPublicBundle();
  }

  /**
   * Step 4: Upload Public Keys to Server
   *
   * SECURITY REQUIREMENT:
   * Send ONLY public components. Private keys NEVER leave device memory or SecureStore.
   */
  exportPublicBundle(): ServerPublicBundle {
    if (!this.isInitialized) {
      throw new Error('SignalService must be initialized before exporting public bundle.');
    }

    return {
      identityPublicKey: this.formatKeyString(this.identityKeyPair.publicKey),
      registrationId: this.registrationId,
      preKeys: this.preKeys.map((k) => ({
        id: k.id,
        publicKey: this.formatKeyString(k.publicKey),
      })),
      signedPreKey: {
        id: this.signedPreKey.id,
        publicKey: this.formatKeyString(this.signedPreKey.publicKey),
        signature: this.formatKeyString(this.signedPreKey.signature),
      },
    };
  }

  /**
   * Step 5: Establish Session with Recipient
   *
   * Includes automated Key-Change Detection to block MitM and alert the user.
   */
  async establishSession(
    recipientAddress: SignalAddress,
    recipientPreKeyBundle: any
  ): Promise<void> {
    await this.ensureInitialized();

    // Key-Change Detection: check recipient's identity public key
    const recipientIdentityKey = recipientPreKeyBundle.identityKey || recipientPreKeyBundle.identityPublicKey;
    if (recipientIdentityKey) {
      const check = await KeyChangeDetector.checkContactKey(
        recipientAddress.name,
        recipientIdentityKey
      );

      if (!check.verified && check.alert) {
        // BLOCK SESSION & THROW: User must manually verify Safety Number change
        throw new KeyChangeException(check.alert);
      }
    }

    // Create session in @toled/signal-expo native engine
    await createSession(recipientAddress, recipientPreKeyBundle);
  }

  /**
   * Step 6: Encrypt Message
   * Converts plaintext string to Uint8Array via TextEncoder and encrypts with recipient session.
   */
  async encryptMessage(
    recipientAddress: SignalAddress,
    messageText: string
  ): Promise<any> {
    await this.ensureInitialized();

    const plaintext = new TextEncoder().encode(messageText);
    const ciphertext = await encrypt(recipientAddress, plaintext);
    return ciphertext;
  }

  /**
   * Step 7: Decrypt Received Message
   * Decrypts ciphertext and decodes Uint8Array into UTF-8 plaintext string.
   */
  async decryptMessage(
    senderAddress: SignalAddress,
    receivedCiphertext: any
  ): Promise<string> {
    await this.ensureInitialized();

    const decrypted = await decrypt(senderAddress, receivedCiphertext);
    const message = new TextDecoder().decode(decrypted.plaintext);
    return message;
  }

  /**
   * Approves a key change after the user confirms the new Safety Number.
   */
  async approveContactKeyChange(contactName: string, newKey: Uint8Array | string): Promise<void> {
    await KeyChangeDetector.approveKeyChange(contactName, newKey);
  }

  private formatKeyString(key: any): string {
    if (typeof key === 'string') return key;
    if (key instanceof Uint8Array || Array.isArray(key)) {
      return btoa(String.fromCharCode(...new Uint8Array(key)));
    }
    return JSON.stringify(key);
  }
}

