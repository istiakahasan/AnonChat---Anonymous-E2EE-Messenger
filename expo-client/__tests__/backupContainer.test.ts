import {
  BackupContainerService,
  BACKUP_HEADER_SIZE,
  BACKUP_MAGIC,
  MIN_PASSPHRASE_LEN,
  encryptPayloadAesGcm,
  decryptPayloadAesGcm,
} from '../src/crypto/backupContainer';

describe('BackupContainerService (Expo / React Native)', () => {
  const strongPassphrase = 'Correct-Horse-Battery-2026!';

  test('validates passphrase policy correctly', () => {
    // Too short
    expect(() => BackupContainerService.validatePassphrase('short123')).toThrow(
      /Passphrase too short/
    );

    // Repeated characters
    expect(() => BackupContainerService.validatePassphrase('aaaaaaaaaaaa')).toThrow(
      /lacks character diversity/
    );

    // Sequential pattern
    expect(() => BackupContainerService.validatePassphrase('abcdefghijkl')).toThrow(
      /simple sequential pattern/
    );

    // Valid strong passphrase
    expect(() => BackupContainerService.validatePassphrase(strongPassphrase)).not.toThrow();
  });

  test('derives 32-byte key from user passphrase', async () => {
    const salt = new Uint8Array(16);
    salt.fill(0x77);

    const keyBytes = await BackupContainerService.deriveBackupKey(
      strongPassphrase,
      salt,
      3,
      16,
      1
    );

    expect(keyBytes).toBeInstanceOf(Uint8Array);
    expect(keyBytes.length).toBe(32);
  });

  test('creates container with 42-byte header and verifies AAD authentication', async () => {
    const sampleDb = new TextEncoder().encode('{"contacts":["bob"],"messages":42}');
    const container = await BackupContainerService.createContainerWithPassphrase(
      strongPassphrase,
      sampleDb,
      3,
      16,
      1
    );

    expect(container.length).toBe(BACKUP_HEADER_SIZE + sampleDb.length + 16);

    const header = BackupContainerService.parseHeader(container);
    expect(header.version).toBe(0x01);
    expect(header.kdfId).toBe(0x01);
    expect(header.timeCost).toBe(3);
    expect(header.memoryExponent).toBe(16);
    expect(header.parallelism).toBe(1);
    expect(header.salt.length).toBe(16);
    expect(header.nonce.length).toBe(12);

    // Decrypt with correct passphrase
    const decrypted = await BackupContainerService.decryptContainerWithPassphrase(
      strongPassphrase,
      container
    );
    expect(new TextDecoder().decode(decrypted)).toBe('{"contacts":["bob"],"messages":42}');
  });

  test('encryptPayloadAesGcm and decryptPayloadAesGcm with raw 32-byte key and headerBytes', async () => {
    const rawKey = new Uint8Array(32);
    rawKey.fill(0x42);
    const nonce = new Uint8Array(12);
    nonce.fill(0x99);
    const headerBytes = new Uint8Array(42);
    headerBytes.fill(0xaa);
    const plaintext = new TextEncoder().encode('Payload encrypted with Sub-Step 3.3 AES-GCM');

    // Encrypt passing raw key and full 42-byte header (AAD automatically sliced to 38 bytes)
    const ciphertext = await encryptPayloadAesGcm(plaintext, rawKey, nonce, headerBytes);
    expect(ciphertext.length).toBe(plaintext.length + 16); // 16-byte auth tag appended

    // Decrypt with matching parameters
    const decrypted = await decryptPayloadAesGcm(ciphertext, rawKey, nonce, headerBytes);
    expect(new TextDecoder().decode(decrypted)).toBe('Payload encrypted with Sub-Step 3.3 AES-GCM');

    // Tampered header (AAD mismatch) triggers decryption failure
    const tamperedHeader = new Uint8Array(headerBytes);
    tamperedHeader[5] ^= 0xff;
    await expect(
      decryptPayloadAesGcm(ciphertext, rawKey, nonce, tamperedHeader)
    ).rejects.toThrow('Incorrect passphrase or corrupted backup file.');
  });

  test('rejects malicious headers violating resource exhaustion defense ceilings', () => {
    const maliciousContainer = new Uint8Array(42 + 32);
    maliciousContainer.set([0x41, 0x4e, 0x4f, 0x4e], 0); // "ANON"
    maliciousContainer[4] = 0x01; // version
    maliciousContainer[5] = 0x01; // kdfId
    maliciousContainer[6] = 3;    // timeCost
    maliciousContainer[7] = 25;   // memoryExponent = 25 > 20 (ceiling violation)
    maliciousContainer[8] = 1;    // parallelism

    expect(() => BackupContainerService.parseHeader(maliciousContainer)).toThrow(
      /resource exhaustion defense/
    );
  });
});

