/**
 * Encrypted IndexedDB Storage using Web Crypto API (AES-256-GCM)
 *
 * SECURITY REQUIREMENT:
 * - Store serialized records in IndexedDB with an additional layer of encryption.
 * - Protects exported Signal sessions, Kyber prekeys, and ratchet state at rest in the browser.
 */

const DB_NAME = 'AnonChat_SignalWasm_EncryptedDB';
const DB_VERSION = 1;
const STORE_SESSIONS = 'encrypted_sessions';
const STORE_KEYS = 'device_keystore';

export class EncryptedIndexedDb {
  private db: IDBDatabase | null = null;
  private masterKey: CryptoKey | null = null;

  async init(): Promise<void> {
    this.db = await this.openDatabase();
    this.masterKey = await this.getOrCreateMasterKey();
  }

  private openDatabase(): Promise<IDBDatabase> {
    return new Promise((resolve, reject) => {
      const request = indexedDB.open(DB_NAME, DB_VERSION);

      request.onupgradeneeded = (event: any) => {
        const db = event.target.result as IDBDatabase;
        if (!db.objectStoreNames.contains(STORE_SESSIONS)) {
          db.createObjectStore(STORE_SESSIONS, { keyPath: 'id' });
        }
        if (!db.objectStoreNames.contains(STORE_KEYS)) {
          db.createObjectStore(STORE_KEYS, { keyPath: 'name' });
        }
      };

      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });
  }

  /**
   * Retrieves or generates a 256-bit AES-GCM non-extractable device master key.
   */
  private async getOrCreateMasterKey(): Promise<CryptoKey> {
    return new Promise(async (resolve, reject) => {
      const tx = this.db!.transaction(STORE_KEYS, 'readwrite');
      const store = tx.objectStore(STORE_KEYS);
      const getReq = store.get('master_storage_key');

      getReq.onsuccess = async () => {
        if (getReq.result) {
          resolve(getReq.result.key);
        } else {
          // Generate hardware/browser non-extractable 256-bit AES-GCM key
          const newKey = await window.crypto.subtle.generateKey(
            { name: 'AES-GCM', length: 256 },
            false, // Non-extractable: prevents JavaScript exfiltration via XSS
            ['encrypt', 'decrypt']
          );

          const putTx = this.db!.transaction(STORE_KEYS, 'readwrite');
          putTx.objectStore(STORE_KEYS).put({ name: 'master_storage_key', key: newKey });
          putTx.oncomplete = () => resolve(newKey);
          putTx.onerror = () => reject(putTx.error);
        }
      };

      getReq.onerror = () => reject(getReq.error);
    });
  }

  /**
   * Encrypts and saves an exported session blob in IndexedDB.
   */
  async saveEncryptedSession(recipientId: string, serializedSession: string): Promise<void> {
    if (!this.masterKey || !this.db) {
      throw new Error('Database not initialized');
    }

    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const encodedData = new TextEncoder().encode(serializedSession);

    const ciphertext = await window.crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      this.masterKey,
      encodedData
    );

    const record = {
      id: recipientId,
      iv: Array.from(iv),
      encryptedBlob: Array.from(new Uint8Array(ciphertext)),
      updatedAt: Date.now(),
    };

    return new Promise((resolve, reject) => {
      const tx = this.db!.transaction(STORE_SESSIONS, 'readwrite');
      tx.objectStore(STORE_SESSIONS).put(record);
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
  }

  /**
   * Loads and decrypts an exported session blob from IndexedDB.
   */
  async loadDecryptedSession(recipientId: string): Promise<string | null> {
    if (!this.masterKey || !this.db) {
      throw new Error('Database not initialized');
    }

    return new Promise((resolve, reject) => {
      const tx = this.db!.transaction(STORE_SESSIONS, 'readonly');
      const req = tx.objectStore(STORE_SESSIONS).get(recipientId);

      req.onsuccess = async () => {
        if (!req.result) {
          return resolve(null);
        }

        try {
          const iv = new Uint8Array(req.result.iv);
          const ciphertext = new Uint8Array(req.result.encryptedBlob);

          const decryptedBuffer = await window.crypto.subtle.decrypt(
            { name: 'AES-GCM', iv },
            this.masterKey!,
            ciphertext
          );

          const sessionString = new TextDecoder().decode(decryptedBuffer);
          resolve(sessionString);
        } catch (err) {
          reject(new Error(`Failed to decrypt session: ${err}`));
        }
      };

      req.onerror = () => reject(req.error);
    });
  }
}

