import 'dart:convert';
import 'dart:typed_data';
import 'package:cryptography/cryptography.dart';

/// AnonChat Self-Describing Backup Container Format (Flutter / Dart)
///
/// Binary Layout (little-endian):
/// Offset  Size  Field
/// 0       4     Magic bytes: "ANON" (0x41 0x4E 0x4F 0x4E)
/// 4       1     Format version: 0x01
/// 5       1     KDF identifier: 0x01 = Argon2id
/// 6       1     Argon2 time cost (iterations), uint8
/// 7       1     Argon2 memory exponent: memory_kib = 1 << exponent
/// 8       1     Argon2 parallelism, uint8
/// 9       16    Salt (random per backup)
/// 25      1     Cipher identifier: 0x01 = AES-256-GCM
/// 26      12    Nonce (random per backup)
/// 38      4     Ciphertext length, uint32 LE
/// 42      N     Ciphertext (includes GCM auth tag as final 16 bytes)

const List<int> backupMagic = [0x41, 0x4E, 0x4F, 0x4E]; // "ANON"
const int backupVersion1 = 0x01;
const int kdfIdArgon2id = 0x01;
const int cipherIdAes256Gcm = 0x01;
const int backupHeaderSize = 42;
const int backupSaltSize = 16;
const int backupNonceSize = 12;
const int backupTagSize = 16;
const int backupAadSize = 38;
const int minPassphraseLen = 12;

// Resource Exhaustion Defense Ceilings (Sub-Step 3.4)
const int maxAllowedMemoryExponent = 20; // 1 << 20 KiB = 1 GiB
const int maxAllowedTimeCost = 10;
const int maxAllowedParallelism = 4;

/// Enforces passphrase policy before key derivation:
/// - Minimum 12 characters
/// - Rejects weak repetitive or monotonic sequential strings
/// - Requires character diversity
void validatePassphrase(String passphrase) {
  if (passphrase.length < minPassphraseLen) {
    throw FormatException(
      'Passphrase too short: minimum $minPassphraseLen characters required (got ${passphrase.length})',
    );
  }

  final uniqueChars = passphrase.split('').toSet();
  if (uniqueChars.length < 5) {
    throw const FormatException('Passphrase is too weak: lacks character diversity (at least 5 unique characters required)');
  }

  // Monotonic sequence detection
  var isAsc = true;
  var isDesc = true;
  for (var i = 1; i < passphrase.length; i++) {
    final diff = passphrase.codeUnitAt(i) - passphrase.codeUnitAt(i - 1);
    if (diff != 1) isAsc = false;
    if (diff != -1) isDesc = false;
  }
  if (isAsc || isDesc) {
    throw const FormatException('Passphrase is too weak: simple sequential pattern');
  }

  final hasLower = RegExp(r'[a-z]').hasMatch(passphrase);
  final hasUpper = RegExp(r'[A-Z]').hasMatch(passphrase);
  final hasDigit = RegExp(r'[0-9]').hasMatch(passphrase);
  final hasSymbol = RegExp(r'[^a-zA-Z0-9]').hasMatch(passphrase);
  final categories = [hasLower, hasUpper, hasDigit, hasSymbol].where((b) => b).length;
  if (categories < 2) {
    throw const FormatException('Passphrase must contain at least 2 character categories (letters, digits, symbols)');
  }
}

/// Derives a 256-bit (32-byte) key from the user's passphrase using Argon2id via package:cryptography.
///
/// Inputs:
/// - passphrase: string, UTF-8 encoded
/// - salt: 16 random bytes (fresh per backup)
/// - timeCost: iterations (e.g. 3)
/// - memoryExponent: memory_kib = 1 << memoryExponent (e.g. 16 -> 65536 KiB)
/// - parallelism: lanes (e.g. 1)
/// Output:
/// - 32-byte key (Uint8List)
Future<Uint8List> deriveBackupKey(
  String passphrase,
  Uint8List salt, {
  int timeCost = 3,
  int memoryExponent = 16,
  int parallelism = 1,
  int hashLength = 32,
}) async {
  validatePassphrase(passphrase);

  if (salt.length < backupSaltSize) {
    throw FormatException('Salt too short: expected $backupSaltSize bytes, got ${salt.length}');
  }

  final memoryKib = 1 << memoryExponent;

  final algorithm = Argon2id(
    memory: memoryKib,
    iterations: timeCost,
    parallelism: parallelism,
    hashLength: hashLength,
  );

  final secretKey = await algorithm.deriveKey(
    secretKey: SecretKey(utf8.encode(passphrase)),
    nonce: salt.sublist(0, backupSaltSize),
  );

  final keyBytes = await secretKey.extractBytes();
  return Uint8List.fromList(keyBytes);
}

class BackupHeader {
  final Uint8List magic;
  final int version;
  final int kdfId;
  final int timeCost;
  final int memoryExponent;
  final int parallelism;
  final Uint8List salt;
  final int cipherId;
  final Uint8List nonce;
  final int ciphertextLen;

  BackupHeader({
    required this.magic,
    required this.version,
    required this.kdfId,
    required this.timeCost,
    required this.memoryExponent,
    required this.parallelism,
    required this.salt,
    required this.cipherId,
    required this.nonce,
    required this.ciphertextLen,
  });

  /// Calculates memory requirement in KiB: memory_kib = 1 << memory_exponent
  int get memoryKib {
    if (memoryExponent >= 31) {
      throw FormatException('Argon2 memory exponent too large: 1 << $memoryExponent');
    }
    return 1 << memoryExponent;
  }

  /// Serializes header to 42 bytes (little-endian)
  Uint8List toBytes() {
    final buffer = Uint8List(backupHeaderSize);
    final data = ByteData.sublistView(buffer);

    buffer.setRange(0, 4, magic);
    buffer[4] = version;
    buffer[5] = kdfId;
    buffer[6] = timeCost;
    buffer[7] = memoryExponent;
    buffer[8] = parallelism;
    buffer.setRange(9, 25, salt);
    buffer[25] = cipherId;
    buffer.setRange(26, 38, nonce);
    data.setUint32(38, ciphertextLen, Endian.little);

    return buffer;
  }

  /// Deserializes and validates a 42-byte binary header
  factory BackupHeader.fromBytes(Uint8List bytes) {
    if (bytes.length < backupHeaderSize) {
      throw FormatException(
        'Backup header truncated: expected at least $backupHeaderSize bytes, got ${bytes.length}',
      );
    }

    for (var i = 0; i < 4; i++) {
      if (bytes[i] != backupMagic[i]) {
        throw const FormatException('Invalid backup container: magic bytes mismatch (not "ANON")');
      }
    }

    final version = bytes[4];
    if (version != backupVersion1) {
      throw FormatException('Unsupported backup format version: 0x${version.toRadixString(16)}');
    }

    final kdfId = bytes[5];
    if (kdfId != kdfIdArgon2id) {
      throw FormatException('Unsupported KDF identifier: 0x${kdfId.toRadixString(16)} (expected 0x01 = Argon2id)');
    }

    final timeCost = bytes[6];
    final memoryExponent = bytes[7];
    final parallelism = bytes[8];

    // Resource Exhaustion Defense: enforce parameter ceilings before Argon2 KDF allocation
    if (memoryExponent > maxAllowedMemoryExponent) {
      throw FormatException(
        'Argon2 parameter exceeds security ceiling: memory_exponent $memoryExponent > $maxAllowedMemoryExponent (resource exhaustion defense)',
      );
    }
    if (timeCost > maxAllowedTimeCost) {
      throw FormatException(
        'Argon2 parameter exceeds security ceiling: time_cost $timeCost > $maxAllowedTimeCost (resource exhaustion defense)',
      );
    }
    if (parallelism > maxAllowedParallelism) {
      throw FormatException(
        'Argon2 parameter exceeds security ceiling: parallelism $parallelism > $maxAllowedParallelism (resource exhaustion defense)',
      );
    }

    final salt = Uint8List.fromList(bytes.sublist(9, 25));

    final cipherId = bytes[25];
    if (cipherId != cipherIdAes256Gcm) {
      throw FormatException('Unsupported cipher identifier: 0x${cipherId.toRadixString(16)} (expected 0x01 = AES-256-GCM)');
    }

    final nonce = Uint8List.fromList(bytes.sublist(26, 38));

    final data = ByteData.sublistView(bytes);
    final ciphertextLen = data.getUint32(38, Endian.little);

    return BackupHeader(
      magic: Uint8List.fromList(bytes.sublist(0, 4)),
      version: version,
      kdfId: kdfId,
      timeCost: timeCost,
      memoryExponent: memoryExponent,
      parallelism: parallelism,
      salt: salt,
      cipherId: cipherId,
      nonce: nonce,
      ciphertextLen: ciphertextLen,
    );
  }
}

class BackupContainer {
  final BackupHeader header;
  final Uint8List ciphertext;

  BackupContainer({
    required this.header,
    required this.ciphertext,
  });

  /// Serializes container into a single contiguous byte buffer:
  /// [42-byte header] + [N-byte ciphertext]
  Uint8List toBytes() {
    final headerBytes = header.toBytes();
    final out = Uint8List(backupHeaderSize + ciphertext.length);
    out.setRange(0, backupHeaderSize, headerBytes);
    out.setRange(backupHeaderSize, out.length, ciphertext);
    return out;
  }

  /// Parses and validates a container from raw file bytes
  factory BackupContainer.fromBytes(Uint8List bytes) {
    if (bytes.length < backupHeaderSize) {
      throw FormatException('Backup file truncated: expected at least $backupHeaderSize bytes');
    }

    final header = BackupHeader.fromBytes(bytes);
    final expectedTotal = backupHeaderSize + header.ciphertextLen;

    if (bytes.length < expectedTotal) {
      throw FormatException(
        'Backup payload truncated: header declared ${header.ciphertextLen} bytes, but got ${bytes.length - backupHeaderSize}',
      );
    }

    final ciphertext = Uint8List.fromList(bytes.sublist(backupHeaderSize, expectedTotal));
    return BackupContainer(header: header, ciphertext: ciphertext);
  }

  /// High-level container creation with user passphrase using Argon2id and AES-256-GCM.
  static Future<BackupContainer> createWithPassphrase(
    String passphrase,
    Uint8List plaintext, {
    int timeCost = 3,
    int memoryExponent = 16,
    int parallelism = 1,
    Uint8List? freshSalt,
    Uint8List? freshNonce,
  }) async {
    validatePassphrase(passphrase);
    final salt = freshSalt ??
        Uint8List.fromList(List<int>.generate(
            backupSaltSize, (_) => (DateTime.now().microsecondsSinceEpoch >> 3) & 0xFF));
    final nonce = freshNonce ??
        Uint8List.fromList(List<int>.generate(
            backupNonceSize, (_) => (DateTime.now().microsecondsSinceEpoch >> 5) & 0xFF));

    final keyBytes = await deriveBackupKey(
      passphrase,
      salt,
      timeCost: timeCost,
      memoryExponent: memoryExponent,
      parallelism: parallelism,
    );

    final header = BackupHeader(
      magic: Uint8List.fromList(backupMagic),
      version: backupVersion1,
      kdfId: kdfIdArgon2id,
      timeCost: timeCost,
      memoryExponent: memoryExponent,
      parallelism: parallelism,
      salt: salt,
      cipherId: cipherIdAes256Gcm,
      nonce: nonce,
      ciphertextLen: plaintext.length + backupTagSize,
    );

    final headerBytes = header.toBytes();
    final aad = headerBytes.sublist(0, backupAadSize);
    final aesGcm = AesGcm.with256Bits();
    final secretBox = await aesGcm.encrypt(
      plaintext,
      secretKey: SecretKey(keyBytes),
      nonce: nonce,
      aad: aad,
    );

    final ciphertext = Uint8List(secretBox.cipherText.length + secretBox.mac.bytes.length);
    ciphertext.setRange(0, secretBox.cipherText.length, secretBox.cipherText);
    ciphertext.setRange(secretBox.cipherText.length, ciphertext.length, secretBox.mac.bytes);

    return BackupContainer(header: header, ciphertext: ciphertext);
  }

  /// High-level container decryption with user passphrase verifying header bytes 0..37 as AAD.
  Future<Uint8List> decryptWithPassphrase(String passphrase) async {
    validatePassphrase(passphrase);
    final keyBytes = await deriveBackupKey(
      passphrase,
      header.salt,
      timeCost: header.timeCost,
      memoryExponent: header.memoryExponent,
      parallelism: header.parallelism,
    );

    if (ciphertext.length < backupTagSize) {
      throw const FormatException('Ciphertext too short');
    }

    final headerBytes = header.toBytes();
    final aad = headerBytes.sublist(0, backupAadSize);
    final ptLen = ciphertext.length - backupTagSize;
    final cipherOnly = ciphertext.sublist(0, ptLen);
    final macBytes = ciphertext.sublist(ptLen);

    final aesGcm = AesGcm.with256Bits();
    final secretBox = SecretBox(
      cipherOnly,
      nonce: header.nonce,
      mac: Mac(macBytes),
    );

    try {
      final decrypted = await aesGcm.decrypt(
        secretBox,
        secretKey: SecretKey(keyBytes),
        aad: aad,
      );

      return Uint8List.fromList(decrypted);
    } catch (_) {
      throw const FormatException('Incorrect passphrase or corrupted backup file.');
    }
  }
}

