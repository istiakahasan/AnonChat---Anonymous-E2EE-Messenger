import 'dart:convert';
import 'dart:typed_data';
import 'package:flutter_test/flutter_test.dart';
import 'package:anonchat_flutter/src/crypto/backup_container.dart';

void main() {
  group('BackupContainer (Flutter / package:cryptography)', () {
    const validPassphrase = 'Correct-Horse-Battery-2026!';

    test('validates passphrase policy correctly', () {
      expect(() => validatePassphrase('short123'), throwsFormatException);
      expect(() => validatePassphrase('aaaaaaaaaaaa'), throwsFormatException);
      expect(() => validatePassphrase('abcdefghijkl'), throwsFormatException);
      expect(() => validatePassphrase(validPassphrase), returnsNormally);
    });

    test('derives 32-byte key using Argon2id', () async {
      final salt = Uint8List(16);
      salt.fillRange(0, 16, 0x42);

      final keyBytes = await deriveBackupKey(
        validPassphrase,
        salt,
        timeCost: 3,
        memoryExponent: 16,
        parallelism: 1,
      );

      expect(keyBytes.length, equals(32));
    });

    test('roundtrips container encryption and decryption with AAD', () async {
      final sampleDb = utf8.encode('{"contacts":["alice"],"messages":100}');
      final container = await BackupContainer.createWithPassphrase(
        validPassphrase,
        Uint8List.fromList(sampleDb),
        timeCost: 3,
        memoryExponent: 16,
        parallelism: 1,
      );

      expect(container.ciphertext.length, equals(sampleDb.length + backupTagSize));

      final decrypted = await container.decryptWithPassphrase(validPassphrase);
      expect(utf8.decode(decrypted), equals('{"contacts":["alice"],"messages":100}'));
    });
  });
}

