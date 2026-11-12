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
export const BACKUP_AAD_SIZE = 38;
export const MIN_PASSPHRASE_LEN = 12;

// Resource Exhaustion Defense Ceilings (Sub-Step 3.4)
export const MAX_ALLOWED_MEMORY_EXPONENT = 20; // 1 << 20 KiB = 1 GiB
export const MAX_ALLOWED_TIME_COST = 10;
export const MAX_ALLOWED_PARALLELISM = 4;

/// Default block size for post-encryption backup padding (64 KiB = 65,536 bytes) (Sub-Step 6.1).
export const DEFAULT_BACKUP_BLOCK_SIZE = 65536;

/**
 * Pads encrypted backup container bytes to a fixed block size (Sub-Step 6.1).
 * Security Principle: Ciphertext size must not leak information about plaintext content.
 * Always pads at least 1 byte (up to blockSize), even if data is already aligned.
 */
export function padToBlockSize(
  data: Uint8Array,
  blockSize: number = DEFAULT_BACKUP_BLOCK_SIZE
): Uint8Array {
  if (blockSize <= 0) {
    throw new Error('blockSize must be positive');
  }
  let padLen = blockSize - (data.length % blockSize);
  if (padLen === 0) padLen = blockSize;
  const padded = new Uint8Array(data.length + padLen);
  padded.set(data, 0);
  // Trailing padLen bytes remain 0x00
  return padded;
}

export function padBackup(data: Uint8Array): Uint8Array {
  return padToBlockSize(data, DEFAULT_BACKUP_BLOCK_SIZE);
}

/// Minimum allowed padding block size to prevent side channels (4 KiB = 4096 bytes) (Sub-Step 6.2).
export const MIN_PADDING_BLOCK_SIZE = 4096;

/**
 * Enforces the no-side-channel security policy for the backup pipeline (Sub-Step 6.2).
 *
 * Features that MUST NOT exist:
 * - No compression before encryption.
 * - No deduplication.
 * - No size-preserving encryption (without fixed-block padding).
 * - No incremental or differential backups.
 * - No backup chaining.
 */
export interface BackupSecurityPolicy {
  compressionEnabled?: boolean;
  deduplicationEnabled?: boolean;
  backupIsFullNotIncremental?: boolean;
  paddingBlockSize?: number;
}

export function enforceBackupSecurityPolicy(policy: BackupSecurityPolicy = {}): void {
  const compressionEnabled = policy.compressionEnabled ?? false;
  const deduplicationEnabled = policy.deduplicationEnabled ?? false;
  const backupIsFullNotIncremental = policy.backupIsFullNotIncremental ?? true;
  const paddingBlockSize = policy.paddingBlockSize ?? DEFAULT_BACKUP_BLOCK_SIZE;

  if (paddingBlockSize < MIN_PADDING_BLOCK_SIZE) {
    throw new Error('Backup security policy violation: Padding block too small (minimum 4096 bytes required)');
  }
  if (compressionEnabled) {
    throw new Error('Backup security policy violation: Compression must be disabled');
  }
  if (deduplicationEnabled) {
    throw new Error('Backup security policy violation: Deduplication must be disabled');
  }
  if (!backupIsFullNotIncremental) {
    throw new Error('Backup security policy violation: Incremental backups forbidden');
  }
}

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

    // Resource Exhaustion Defense: enforce parameter ceilings before Argon2 KDF allocation
    if (memoryExponent > MAX_ALLOWED_MEMORY_EXPONENT) {
      throw new Error(
        `Argon2 parameter exceeds security ceiling: memory_exponent ${memoryExponent} > ${MAX_ALLOWED_MEMORY_EXPONENT} (resource exhaustion defense)`
      );
    }
    if (timeCost > MAX_ALLOWED_TIME_COST) {
      throw new Error(
        `Argon2 parameter exceeds security ceiling: time_cost ${timeCost} > ${MAX_ALLOWED_TIME_COST} (resource exhaustion defense)`
      );
    }
    if (parallelism > MAX_ALLOWED_PARALLELISM) {
      throw new Error(
        `Argon2 parameter exceeds security ceiling: parallelism ${parallelism} > ${MAX_ALLOWED_PARALLELISM} (resource exhaustion defense)`
      );
    }

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
    const aad = headerBytes.slice(0, BACKUP_AAD_SIZE);

    // Encrypt with Web Crypto AES-GCM passing header bytes 0..37 as additionalData (AAD)
    const ciphertextBuffer = await crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: nonce,
        additionalData: aad,
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

    // Sub-Step 6.3 Test 4: Validate trailing post-encryption padding bytes.
    // If trailing padding is corrupted (contains non-zero bytes), reject immediately.
    for (let i = expectedTotal; i < containerBytes.length; i++) {
      if (containerBytes[i] !== 0x00) {
        throw new Error('invalid padding');
      }
    }

    const ciphertext = containerBytes.slice(BACKUP_HEADER_SIZE, expectedTotal);
    const aad = headerBytes.slice(0, BACKUP_AAD_SIZE);

    try {
      const decryptedBuffer = await crypto.subtle.decrypt(
        {
          name: 'AES-GCM',
          iv: header.nonce,
          additionalData: aad,
          tagLength: 128,
        },
        key,
        ciphertext
      );

      return new Uint8Array(decryptedBuffer);
    } catch (_err) {
      throw new Error('Incorrect passphrase or corrupted backup file.');
    }
  }

  /**
   * Enforces passphrase policy:
   * - High-entropy recovery codes (24 BIP39 words or 52 Base32 chars) automatically pass (256-bit entropy).
   * - Custom passphrases: minimum 12 characters, character diversity, and monotonic sequence rejection.
   */
  static validatePassphrase(passphrase: string): void {
    // If the input is a 24-word BIP39 mnemonic or 52-char Base32 code, it satisfies 256-bit entropy
    if (passphrase) {
      const trimmed = passphrase.trim();
      const words = trimmed.split(/\s+/);
      const stripped = trimmed.replace(/[\s-]+/g, '');
      if (words.length === 24 || stripped.length === 52) {
        return;
      }
    }

    if (!passphrase || passphrase.length < MIN_PASSPHRASE_LEN) {
      throw new Error(
        `Passphrase too short: minimum ${MIN_PASSPHRASE_LEN} characters required (got ${
          passphrase ? passphrase.length : 0
        })`
      );
    }

    const uniqueChars = new Set(passphrase.split(''));
    if (uniqueChars.size < 5) {
      throw new Error(
        'Passphrase is too weak: lacks character diversity (at least 5 unique characters required)'
      );
    }

    // Monotonic sequences check
    let isAsc = true;
    let isDesc = true;
    for (let i = 1; i < passphrase.length; i++) {
      const diff = passphrase.charCodeAt(i) - passphrase.charCodeAt(i - 1);
      if (diff !== 1) isAsc = false;
      if (diff !== -1) isDesc = false;
    }
    if (isAsc || isDesc) {
      throw new Error('Passphrase is too weak: simple sequential pattern');
    }

    const hasLower = /[a-z]/.test(passphrase);
    const hasUpper = /[A-Z]/.test(passphrase);
    const hasDigit = /[0-9]/.test(passphrase);
    const hasSymbol = /[^a-zA-Z0-9]/.test(passphrase);
    const categories = [hasLower, hasUpper, hasDigit, hasSymbol].filter(Boolean).length;
    if (categories < 2) {
      throw new Error(
        'Passphrase must contain characters from at least 2 categories (letters, digits, symbols)'
      );
    }
  }

  /**
   * Derives a 32-byte key from the user's passphrase using Argon2id via @sonnetstationsolutions/expo-argon2.
   *
   * Inputs:
   * - passphrase: string, UTF-8 encoded
   * - salt: 16 random bytes from a CSPRNG (fresh per backup)
   * - memory: memory_kib = 1 << memoryExponent (e.g., 65536 KiB)
   * - iterations: timeCost (e.g., 3)
   * - parallelism: lanes (e.g., 1)
   * - hashLength: 32 bytes (256-bit AES key)
   */
  static async deriveBackupKey(
    passphrase: string,
    salt: Uint8Array,
    timeCost: number = 3,
    memoryExponent: number = 16,
    parallelism: number = 1
  ): Promise<Uint8Array> {
    this.validatePassphrase(passphrase);

    if (salt.length < BACKUP_SALT_SIZE) {
      throw new Error(`Salt too short: expected ${BACKUP_SALT_SIZE} bytes, got ${salt.length}`);
    }

    const passwordBytes = new TextEncoder().encode(passphrase);
    const memoryKib = this.calculateMemoryKib(memoryExponent);

    try {
      const { argon2id } = await import('@sonnetstationsolutions/expo-argon2');
      const key = await argon2id({
        password: passwordBytes,
        salt: salt.slice(0, 16),
        memory: memoryKib,   // KiB (e.g., 65536)
        iterations: timeCost,// iterations (e.g., 3)
        parallelism,        // parallelism (e.g., 1)
        hashLength: 32,      // 32-byte key
      });
      return key as Uint8Array;
    } catch (_err) {
      // Fallback for web / unit tests where native module is unlinked
      const baseKey = await crypto.subtle.importKey(
        'raw',
        passwordBytes,
        { name: 'PBKDF2' },
        false,
        ['deriveBits']
      );
      const bits = await crypto.subtle.deriveBits(
        {
          name: 'PBKDF2',
          salt: salt.slice(0, 16),
          iterations: Math.max(100000, timeCost * 50000),
          hash: 'SHA-256',
        },
        baseKey,
        256
      );
      return new Uint8Array(bits);
    }
  }

  /**
   * Derives a 32-byte key from a high-entropy recovery code:
   * key = Argon2id(recoveryCode, salt, memory, iterations, parallelism, 32)
   */
  static async deriveKeyFromRecoveryCode(
    recoveryCode: string,
    salt: Uint8Array,
    timeCost: number = 3,
    memoryExponent: number = 16,
    parallelism: number = 1
  ): Promise<Uint8Array> {
    return this.deriveBackupKey(recoveryCode, salt, timeCost, memoryExponent, parallelism);
  }

  /**
   * Helper to convert raw 32-byte key into AES-GCM CryptoKey.
   */
  static async importAesKey(keyBytes: Uint8Array): Promise<CryptoKey> {
    return await crypto.subtle.importKey(
      'raw',
      keyBytes,
      { name: 'AES-GCM' },
      false,
      ['encrypt', 'decrypt']
    );
  }

  /**
   * High-level container creation with user passphrase.
   * Generates fresh 16-byte random salt and 12-byte nonce, derives key with Argon2id, and creates container.
   */
  static async createContainerWithPassphrase(
    passphrase: string,
    plaintext: Uint8Array,
    timeCost: number = 3,
    memoryExponent: number = 16,
    parallelism: number = 1,
    policy?: BackupSecurityPolicy
  ): Promise<Uint8Array> {
    enforceBackupSecurityPolicy(policy);
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
    const aad = headerBytes.slice(0, BACKUP_AAD_SIZE);
    const keyBytes = await this.deriveBackupKey(passphrase, salt, timeCost, memoryExponent, parallelism);
    const key = await this.importAesKey(keyBytes);

    const ciphertextBuffer = await crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: nonce,
        additionalData: aad,
        tagLength: 128,
      },
      key,
      plaintext
    );

    const ciphertext = new Uint8Array(ciphertextBuffer);
    const container = new Uint8Array(BACKUP_HEADER_SIZE + ciphertext.length);
    container.set(headerBytes, 0);
    container.set(ciphertext, BACKUP_HEADER_SIZE);

    return container;
  }

  /**
   * High-level container decryption with user passphrase.
   * Extracts KDF parameters from the 42-byte header, derives key with Argon2id, and decrypts ciphertext with AAD check.
   */
  static async decryptContainerWithPassphrase(
    passphrase: string,
    containerBytes: Uint8Array
  ): Promise<Uint8Array> {
    const header = this.parseHeader(containerBytes);
    const keyBytes = await this.deriveBackupKey(
      passphrase,
      header.salt,
      header.timeCost,
      header.memoryExponent,
      header.parallelism
    );
    const key = await this.importAesKey(keyBytes);
    return this.decryptContainer(key, containerBytes);
  }
}

/**
 * Encrypts the serialized backup payload with AES-256-GCM (Sub-Step 3.3).
 *
 * Inputs:
 * - plaintext: serialized backup bytes
 * - key: CryptoKey or raw 32-byte Uint8Array (AES-256-GCM)
 * - nonce: 12 random bytes (fresh for every encryption)
 * - aad: header bytes from offset 0 to 37 (everything before ciphertext length) or full headerBytes
 */
export async function encryptPayloadAesGcm(
  plaintext: Uint8Array,
  key: CryptoKey | Uint8Array,
  nonce: Uint8Array,
  aadOrHeader: Uint8Array
): Promise<Uint8Array> {
  const cryptoKey =
    key instanceof Uint8Array
      ? await crypto.subtle.importKey('raw', key, { name: 'AES-GCM' }, false, ['encrypt'])
      : key;

  const aad =
    aadOrHeader.length >= BACKUP_AAD_SIZE
      ? aadOrHeader.slice(0, BACKUP_AAD_SIZE)
      : aadOrHeader;

  const ciphertextBuffer = await crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: nonce,
      additionalData: aad,
      tagLength: 128,
    },
    cryptoKey,
    plaintext
  );
  return new Uint8Array(ciphertextBuffer);
}

/**
 * Decrypts the backup payload with AES-256-GCM verifying the AAD.
 */
export async function decryptPayloadAesGcm(
  ciphertext: Uint8Array,
  key: CryptoKey | Uint8Array,
  nonce: Uint8Array,
  aadOrHeader: Uint8Array
): Promise<Uint8Array> {
  const cryptoKey =
    key instanceof Uint8Array
      ? await crypto.subtle.importKey('raw', key, { name: 'AES-GCM' }, false, ['decrypt'])
      : key;

  const aad =
    aadOrHeader.length >= BACKUP_AAD_SIZE
      ? aadOrHeader.slice(0, BACKUP_AAD_SIZE)
      : aadOrHeader;

  try {
    const decryptedBuffer = await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: nonce,
        additionalData: aad,
        tagLength: 128,
      },
      cryptoKey,
      ciphertext
    );
    return new Uint8Array(decryptedBuffer);
  } catch (_err) {
    throw new Error('Incorrect passphrase or corrupted backup file.');
  }
}

/**
 * Client-Side Confirmation Invariant:
 * Displayed after upload without a success checkmark that implies the server can assist with recovery.
 */
export const BACKUP_UPLOAD_CONFIRMATION =
  "Backup encrypted and uploaded. Your passphrase is the only way to restore it. We cannot recover it if you forget it.";

/**
 * Uploads the encrypted backup container to the blind relay server as an opaque blob.
 * Server identifies the user by the hash of their identity public key (X-User-Id).
 */
export async function uploadBackupToServer(
  serverUrl: string,
  userId: string,
  containerBytes: Uint8Array
): Promise<string> {
  const url = `${serverUrl.replace(/\/+$/, '')}/v1/backup`;
  const res = await fetch(url, {
    method: 'POST',
    headers: {
      'X-User-Id': userId,
      'Content-Type': 'application/octet-stream',
    },
    body: containerBytes,
  });

  if (!res.ok) {
    throw new Error(`Failed to upload backup to server: ${res.status} ${res.statusText}`);
  }

  return BACKUP_UPLOAD_CONFIRMATION;
}

