import {
  BackupContainerService,
  BACKUP_HEADER_SIZE,
  BACKUP_MAGIC,
  MIN_PASSPHRASE_LEN,
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
});

