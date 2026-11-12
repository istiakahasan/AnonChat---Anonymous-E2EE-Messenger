/**
 * AnonChat Self-Describing Backup Container Format (TypeScript / Expo)
 *
 * Binary Layout (little-endian):
 * Offset  Size  Field
 * 0       4     Magic bytes: "ANON" (0x41 0x4E 0x4F 0x4E)
 * 4       1     Format version: 0x01
 * 5       1     KDF identifier: 0x01 = Argon2id
 * 6       1     Argon2 time cost (iterations), uint8
 * 7       1     Argon2 memory exponent: memory_kib = 1 << exponent
 * 8       1     Argon2 parallelism, uint8
 * 9       16    Salt (random per backup)
 * 25      1     Cipher identifier: 0x01 = AES-256-GCM
 * 26      12    Nonce (random per backup)
 * 38      4     Ciphertext length, uint32 LE
 * 42      N     Ciphertext (includes GCM auth tag as final 16 bytes)
 */

export const BACKUP_MAGIC = new Uint8Array([0x41, 0x4e, 0x4f, 0x4e]); // "ANON"
export const BACKUP_VERSION_1 = 0x01;
export const KDF_ID_ARGON2ID = 0x01;
export const CIPHER_ID_AES_256_GCM = 0x01;
export const BACKUP_HEADER_SIZE = 42;
export const BACKUP_SALT_SIZE = 16;
export const BACKUP_NONCE_SIZE = 12;
export const BACKUP_TAG_SIZE = 16;

export interface BackupHeader {
  magic: Uint8Array;
  version: number;
  kdfId: number;
  timeCost: number;
  memoryExponent: number;
  parallelism: number;
  salt: Uint8Array;
  cipherId: number;
  nonce: Uint8Array;
  ciphertextLen: number;
}

export class BackupContainerService {
  /**
   * Serializes a BackupHeader object into its exact 42-byte little-endian binary representation.
   */
  static serializeHeader(header: BackupHeader): Uint8Array {
    const buffer = new ArrayBuffer(BACKUP_HEADER_SIZE);
    const view = new DataView(buffer);
    const bytes = new Uint8Array(buffer);

    // 0..4: Magic
    bytes.set(header.magic, 0);
    // 4: Version
    bytes[4] = header.version;
    // 5: KDF identifier
    bytes[5] = header.kdfId;
    // 6: Time cost
    bytes[6] = header.timeCost;
    // 7: Memory exponent
    bytes[7] = header.memoryExponent;
    // 8: Parallelism
    bytes[8] = header.parallelism;
    // 9..25: Salt (16 bytes)
    bytes.set(header.salt, 9);
    // 25: Cipher identifier
    bytes[25] = header.cipherId;
    // 26..38: Nonce (12 bytes)
    bytes.set(header.nonce, 26);
    // 38..42: Ciphertext length (uint32 Little-Endian)
    view.setUint32(38, header.ciphertextLen, true);

    return bytes;
  }

  /**
   * Parses and validates a 42-byte binary header.
   */
  static parseHeader(data: Uint8Array): BackupHeader {
    if (data.length < BACKUP_HEADER_SIZE) {
      throw new Error(`Backup header truncated: expected at least ${BACKUP_HEADER_SIZE} bytes, got ${data.length}`);
    }

    // Verify magic bytes
    for (let i = 0; i < 4; i++) {
      if (data[i] !== BACKUP_MAGIC[i]) {
        throw new Error('Invalid backup container: magic bytes mismatch (not "ANON")');
      }
    }

    const version = data[4];
    if (version !== BACKUP_VERSION_1) {
      throw new Error(`Unsupported backup format version: 0x${version.toString(16).padStart(2, '0')}`);
    }

    const kdfId = data[5];
    if (kdfId !== KDF_ID_ARGON2ID) {
      throw new Error(`Unsupported KDF identifier: 0x${kdfId.toString(16).padStart(2, '0')} (expected 0x01 = Argon2id)`);
    }

    const timeCost = data[6];
    const memoryExponent = data[7];
    const parallelism = data[8];

    const salt = data.slice(9, 25);

    const cipherId = data[25];
    if (cipherId !== CIPHER_ID_AES_256_GCM) {
      throw new Error(`Unsupported cipher identifier: 0x${cipherId.toString(16).padStart(2, '0')} (expected 0x01 = AES-256-GCM)`);
    }

    const nonce = data.slice(26, 38);

    const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
    const ciphertextLen = view.getUint32(38, true); // Little-endian

    return {
      magic: data.slice(0, 4),
      version,
      kdfId,
      timeCost,
      memoryExponent,
      parallelism,
      salt,
      cipherId,
      nonce,
      ciphertextLen,
    };
  }

  /**
   * Calculates memory requirement in KiB from memory exponent:
   * memory_kib = 1 << memory_exponent
   */
  static calculateMemoryKib(memoryExponent: number): number {
    if (memoryExponent >= 31) {
      throw new Error(`Argon2 memory exponent too large: 1 << ${memoryExponent}`);
    }
    return 1 << memoryExponent;
  }

  /**
   * Encrypts plaintext data using AES-256-GCM with the 42-byte header authenticated as AAD.
   */
  static async createContainer(
    key: CryptoKey,
    plaintext: Uint8Array,
    timeCost: number = 3,
    memoryExponent: number = 16,
    parallelism: number = 4
  ): Promise<Uint8Array> {
    const salt = crypto.getRandomValues(new Uint8Array(BACKUP_SALT_SIZE));
    const nonce = crypto.getRandomValues(new Uint8Array(BACKUP_NONCE_SIZE));
    const ciphertextLen = plaintext.length + BACKUP_TAG_SIZE;

    const header: BackupHeader = {
      magic: BACKUP_MAGIC,
      version: BACKUP_VERSION_1,
      kdfId: KDF_ID_ARGON2ID,
      timeCost,
      memoryExponent,
      parallelism,
      salt,
      cipherId: CIPHER_ID_AES_256_GCM,
      nonce,
      ciphertextLen,
    };

    const headerBytes = this.serializeHeader(header);

    // Encrypt with Web Crypto AES-GCM passing the full 42-byte header as additionalData (AAD)
    const ciphertextBuffer = await crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: nonce,
        additionalData: headerBytes,
        tagLength: 128,
      },
      key,
      plaintext
    );

    const ciphertext = new Uint8Array(ciphertextBuffer);

    // Combine header (42 bytes) + ciphertext (N bytes)
    const container = new Uint8Array(BACKUP_HEADER_SIZE + ciphertext.length);
    container.set(headerBytes, 0);
    container.set(ciphertext, BACKUP_HEADER_SIZE);

    return container;
  }

  /**
   * Parses and decrypts an AnonChat backup container.
   */
  static async decryptContainer(
    key: CryptoKey,
    containerBytes: Uint8Array
  ): Promise<Uint8Array> {
    if (containerBytes.length < BACKUP_HEADER_SIZE) {
      throw new Error(`Backup container too short: ${containerBytes.length} bytes`);
    }

    const header = this.parseHeader(containerBytes);
    const headerBytes = containerBytes.slice(0, BACKUP_HEADER_SIZE);
    const expectedTotal = BACKUP_HEADER_SIZE + header.ciphertextLen;

    if (containerBytes.length < expectedTotal) {
      throw new Error(
        `Backup payload truncated: expected ${expectedTotal} bytes, got ${containerBytes.length}`
      );
    }

    const ciphertext = containerBytes.slice(BACKUP_HEADER_SIZE, expectedTotal);

    const decryptedBuffer = await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: header.nonce,
        additionalData: headerBytes,
        tagLength: 128,
      },
      key,
      ciphertext
    );

    return new Uint8Array(decryptedBuffer);
  }
}
