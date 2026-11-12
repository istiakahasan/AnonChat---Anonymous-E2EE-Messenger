import 'dart:typed_data';

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
}
