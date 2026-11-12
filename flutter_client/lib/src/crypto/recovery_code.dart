import 'dart:math';
import 'dart:typed_data';
import 'package:crypto/crypto.dart';
import 'bip39_words.dart';

/// High-Entropy Recovery Code Implementation (Flutter / Dart)
///
/// Implements:
/// - Option B (Recommended): 24-word BIP39 mnemonic phrase (256-bit entropy + 8-bit SHA-256 checksum)
/// - Option A: Crockford Base32 52-character recovery code in 13 groups of 4 separated by spaces
class RecoveryCode {
  static const String crockfordAlphabet = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

  /// Generates 256 bits (32 bytes) of CSPRNG entropy.
  static Uint8List generateEntropy256() {
    final random = Random.secure();
    final bytes = Uint8List(32);
    for (int i = 0; i < 32; i++) {
      bytes[i] = random.nextInt(256);
    }
    return bytes;
  }

  /// Encodes 32-byte (256-bit) entropy into a 24-word BIP39 mnemonic phrase.
  static String entropyToBip39(Uint8List entropy) {
    if (entropy.length != 32) {
      throw ArgumentError('Invalid entropy length: expected 32 bytes, got ${entropy.length}');
    }

    // 1. Calculate 8-bit checksum: first byte of SHA-256(entropy)
    final digest = sha256.convert(entropy).bytes;
    final checksum = digest[0];

    // 2. Build 264-bit stream
    final bits = <int>[];
    for (int i = 0; i < entropy.length; i++) {
      final byte = entropy[i];
      for (int bitIdx = 7; bitIdx >= 0; bitIdx--) {
        bits.add((byte >> bitIdx) & 1);
      }
    }
    for (int bitIdx = 7; bitIdx >= 0; bitIdx--) {
      bits.add((checksum >> bitIdx) & 1);
    }

    // 3. Extract 24 chunks of 11 bits each
    final words = <String>[];
    for (int i = 0; i < 24; i++) {
      int wordIdx = 0;
      for (int bitOffset = 0; bitOffset < 11; bitOffset++) {
        wordIdx = (wordIdx << 1) | bits[i * 11 + bitOffset];
      }
      words.add(bip39EnglishWordlist[wordIdx]);
    }

    return words.join(' ');
  }

  /// Decodes and validates a 24-word BIP39 mnemonic phrase, recovering 32-byte entropy.
  static Uint8List bip39ToEntropy(String phrase) {
    final words = phrase.trim().toLowerCase().split(RegExp(r'\s+'));
    if (words.length != 24) {
      throw FormatException('Invalid word count: expected 24 words, got ${words.length}');
    }

    final bits = <int>[];
    for (int i = 0; i < words.length; i++) {
      final word = words[i];
      final wordIdx = bip39EnglishWordlist.indexOf(word);
      if (wordIdx == -1) {
        throw FormatException("Word not found in BIP39 wordlist: '$word' at position ${i + 1}");
      }
      for (int bitIdx = 10; bitIdx >= 0; bitIdx--) {
        bits.add((wordIdx >> bitIdx) & 1);
      }
    }

    // Extract 32-byte entropy
    final entropy = Uint8List(32);
    for (int byteIdx = 0; byteIdx < 32; byteIdx++) {
      int byte = 0;
      for (int bitOffset = 0; bitOffset < 8; bitOffset++) {
        byte = (byte << 1) | bits[byteIdx * 8 + bitOffset];
      }
      entropy[byteIdx] = byte;
    }

    // Extract 8-bit checksum
    int expectedChecksum = 0;
    for (int bitOffset = 0; bitOffset < 8; bitOffset++) {
      expectedChecksum = (expectedChecksum << 1) | bits[256 + bitOffset];
    }

    // Verify SHA-256 checksum
    final computedChecksum = sha256.convert(entropy).bytes[0];
    if (computedChecksum != expectedChecksum) {
      throw const FormatException('Invalid BIP39 checksum: phrase may be mistyped or corrupted');
    }

    return entropy;
  }

  /// Generates a fresh 24-word BIP39 recovery code (Option B - Recommended).
  static String generateBip39() {
    final entropy = generateEntropy256();
    return entropyToBip39(entropy);
  }

  /// Encodes 32-byte (256-bit) entropy into Crockford Base32 (Option A: 52 characters in groups of 4).
  static String entropyToBase32(Uint8List entropy) {
    if (entropy.length != 32) {
      throw ArgumentError('Invalid entropy length: expected 32 bytes, got ${entropy.length}');
    }

    final bits = <int>[];
    for (int i = 0; i < entropy.length; i++) {
      final byte = entropy[i];
      for (int bitIdx = 7; bitIdx >= 0; bitIdx--) {
        bits.add((byte >> bitIdx) & 1);
      }
    }
    bits.addAll([0, 0, 0, 0]); // 4 padding bits -> 260 bits

    final chars = <String>[];
    for (int i = 0; i < 52; i++) {
      int val = 0;
      for (int bitOffset = 0; bitOffset < 5; bitOffset++) {
        val = (val << 1) | bits[i * 5 + bitOffset];
      }
      chars.add(crockfordAlphabet[val]);
    }

    final groups = <String>[];
    for (int i = 0; i < 52; i += 4) {
      groups.add(chars.sublist(i, i + 4).join(''));
    }
    return groups.join(' ');
  }

  /// Decodes Crockford Base32 recovery code into 32-byte entropy.
  static Uint8List base32ToEntropy(String code) {
    String normalized = code.replaceAll(RegExp(r'[\s-]+'), '').toUpperCase();
    normalized = normalized.replaceAll('O', '0').replaceAll(RegExp(r'[IL]'), '1');

    if (normalized.length != 52) {
      throw FormatException('Invalid Base32 length: expected 52 characters, got ${normalized.length}');
    }

    final bits = <int>[];
    for (int i = 0; i < normalized.length; i++) {
      final c = normalized[i];
      final idx = crockfordAlphabet.indexOf(c);
      if (idx == -1) {
        throw FormatException("Invalid Base32 character: '$c'");
      }
      for (int bitIdx = 4; bitIdx >= 0; bitIdx--) {
        bits.add((idx >> bitIdx) & 1);
      }
    }

    final entropy = Uint8List(32);
    for (int byteIdx = 0; byteIdx < 32; byteIdx++) {
      int byte = 0;
      for (int bitOffset = 0; bitOffset < 8; bitOffset++) {
        byte = (byte << 1) | bits[byteIdx * 8 + bitOffset];
      }
      entropy[byteIdx] = byte;
    }

    return entropy;
  }

  /// Generates a fresh Crockford Base32 recovery code (Option A: 52 characters in 13 groups of 4).
  static String generateBase32() {
    final entropy = generateEntropy256();
    return entropyToBase32(entropy);
  }

  /// Unified validator: Automatically detects and validates BIP39 24 words or Base32 52 chars.
  static Uint8List validate(String input) {
    final trimmed = input.trim();
    final words = trimmed.split(RegExp(r'\s+'));

    if (words.length == 24) {
      return bip39ToEntropy(trimmed);
    }

    final stripped = trimmed.replaceAll(RegExp(r'[\s-]+'), '');
    if (stripped.length == 52) {
      return base32ToEntropy(trimmed);
    }

    throw const FormatException('Unrecognized recovery code format: must be 24 BIP39 words or 52 Base32 characters');
  }
}
