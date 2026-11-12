import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_client/src/crypto/recovery_code.dart';

void main() {
  group('RecoveryCode Specification (BIP39 & Base32)', () {
    test('generates 24-word BIP39 phrase and decodes back to entropy', () {
      final phrase = RecoveryCode.generateBip39();
      final words = phrase.split(' ');
      expect(words.length, equals(24));

      final entropy = RecoveryCode.bip39ToEntropy(phrase);
      expect(entropy.length, equals(32));

      final reEncoded = RecoveryCode.entropyToBip39(entropy);
      expect(reEncoded, equals(phrase));
    });

    test('detects BIP39 checksum corruption', () {
      final phrase = RecoveryCode.generateBip39();
      final words = phrase.split(' ');
      words[23] = words[23] == 'abandon' ? 'ability' : 'abandon';
      final tampered = words.join(' ');

      expect(
        () => RecoveryCode.bip39ToEntropy(tampered),
        throwsA(isA<FormatException>()),
      );
    });

    test('detects invalid word in BIP39 phrase', () {
      final phrase = RecoveryCode.generateBip39();
      final words = phrase.split(' ');
      words[0] = 'notarealword123';
      final tampered = words.join(' ');

      expect(
        () => RecoveryCode.bip39ToEntropy(tampered),
        throwsA(isA<FormatException>()),
      );
    });

    test('generates Crockford Base32 recovery code (52 characters in 13 groups of 4)', () {
      final code = RecoveryCode.generateBase32();
      final groups = code.split(' ');
      expect(groups.length, equals(13));
      for (final g in groups) {
        expect(g.length, equals(4));
      }

      final entropy = RecoveryCode.base32ToEntropy(code);
      expect(entropy.length, equals(32));

      final reEncoded = RecoveryCode.entropyToBase32(entropy);
      expect(reEncoded, equals(code));
    });

    test('unified validator supports both BIP39 and Base32 recovery codes', () {
      final bip39 = RecoveryCode.generateBip39();
      final base32 = RecoveryCode.generateBase32();

      final ent1 = RecoveryCode.validate(bip39);
      final ent2 = RecoveryCode.validate(base32);

      expect(ent1.length, equals(32));
      expect(ent2.length, equals(32));

      expect(() => RecoveryCode.validate('invalid short code'), throwsA(isA<FormatException>()));
    });
  });
}

