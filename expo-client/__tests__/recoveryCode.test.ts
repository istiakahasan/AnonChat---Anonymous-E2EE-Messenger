import {
  generateBip39RecoveryCode,
  validateBip39RecoveryCode,
  entropyToBip39,
  bip39ToEntropy,
  generateBase32RecoveryCode,
  entropyToBase32,
  base32ToEntropy,
  validateRecoveryCode,
} from '../src/crypto/recoveryCode';

describe('High-Entropy Recovery Code Specification (BIP39 & Base32)', () => {
  test('generates a 24-word BIP39 mnemonic phrase and roundtrips to entropy', async () => {
    const code = await generateBip39RecoveryCode();
    const words = code.split(' ');
    expect(words.length).toBe(24);

    const entropy = await bip39ToEntropy(code);
    expect(entropy.length).toBe(32);

    const reEncoded = await entropyToBip39(entropy);
    expect(reEncoded).toBe(code);
  });

  test('detects BIP39 checksum tampering', async () => {
    const code = await generateBip39RecoveryCode();
    const words = code.split(' ');
    // Swap last word to corrupt checksum
    words[23] = words[23] === 'abandon' ? 'ability' : 'abandon';
    const tampered = words.join(' ');

    await expect(bip39ToEntropy(tampered)).rejects.toThrow(/Invalid BIP39 checksum/);
  });

  test('detects invalid word in BIP39 phrase', async () => {
    const code = await generateBip39RecoveryCode();
    const words = code.split(' ');
    words[0] = 'notabip39word';
    const tampered = words.join(' ');

    await expect(bip39ToEntropy(tampered)).rejects.toThrow(/Word not found in BIP39 wordlist/);
  });

  test('generates Crockford Base32 recovery code (52 chars in 13 groups of 4)', () => {
    const code = generateBase32RecoveryCode();
    const groups = code.split(' ');
    expect(groups.length).toBe(13);
    for (const g of groups) {
      expect(g.length).toBe(4);
    }

    const entropy = base32ToEntropy(code);
    expect(entropy.length).toBe(32);

    const reEncoded = entropyToBase32(entropy);
    expect(reEncoded).toBe(code);
  });

  test('unified validator supports both BIP39 and Base32 recovery codes', async () => {
    const bip39 = await generateBip39RecoveryCode();
    const base32 = generateBase32RecoveryCode();

    const ent1 = await validateRecoveryCode(bip39);
    const ent2 = await validateRecoveryCode(base32);

    expect(ent1.length).toBe(32);
    expect(ent2.length).toBe(32);

    await expect(validateRecoveryCode('too short')).rejects.toThrow(/Unrecognized recovery code format/);
  });
});
