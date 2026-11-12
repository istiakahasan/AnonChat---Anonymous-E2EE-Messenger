/**
 * Unit Test for KeyChangeDetector
 * Verifies safety number verification, first-contact trust, and critical key change detection.
 */

import { KeyChangeDetector } from '../src/crypto/keyChangeDetector';
import { SecureStorageService } from '../src/crypto/secureStorage';

// In-memory mock for expo-secure-store
const mockStorage: Record<string, string> = {};

jest.mock('expo-secure-store', () => ({
  setItemAsync: jest.fn(async (key: string, value: string) => {
    mockStorage[key] = value;
  }),
  getItemAsync: jest.fn(async (key: string) => {
    return mockStorage[key] || null;
  }),
  deleteItemAsync: jest.fn(async (key: string) => {
    delete mockStorage[key];
  }),
  WHEN_UNLOCKED_THIS_DEVICE_ONLY: 1,
}));

describe('KeyChangeDetector', () => {
  beforeEach(() => {
    for (const k in mockStorage) delete mockStorage[k];
  });

  test('First contact interaction trusts and saves key', async () => {
    const contact = 'bob';
    const initialKey = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);

    const result = await KeyChangeDetector.checkContactKey(contact, initialKey);
    expect(result.verified).toBe(true);
    expect(result.alert).toBeUndefined();
  });

  test('Subsequent message with same key succeeds', async () => {
    const contact = 'bob';
    const key = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);

    await KeyChangeDetector.checkContactKey(contact, key);
    const secondCheck = await KeyChangeDetector.checkContactKey(contact, key);
    expect(secondCheck.verified).toBe(true);
  });

  test('Identity key change triggers critical alert and blocks transmission', async () => {
    const contact = 'bob';
    const originalKey = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
    const changedKey = new Uint8Array([9, 9, 9, 9, 9, 9, 9, 9]);

    // Initial trusted contact
    await KeyChangeDetector.checkContactKey(contact, originalKey);

    // Attacker or reinstalled app presents new key
    const result = await KeyChangeDetector.checkContactKey(contact, changedKey);

    expect(result.verified).toBe(false);
    expect(result.alert).toBeDefined();
    expect(result.alert?.contactName).toBe('bob');
    expect(result.alert?.previousKeyFingerprint).not.toBe(result.alert?.newKeyFingerprint);
  });

  test('User approval updates trusted key and restores transmission', async () => {
    const contact = 'bob';
    const originalKey = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
    const newKey = new Uint8Array([9, 9, 9, 9, 9, 9, 9, 9]);

    await KeyChangeDetector.checkContactKey(contact, originalKey);

    // User explicitly approves new Safety Number
    await KeyChangeDetector.approveKeyChange(contact, newKey);

    // Next check should now verify successfully
    const check = await KeyChangeDetector.checkContactKey(contact, newKey);
    expect(check.verified).toBe(true);
  });
});

