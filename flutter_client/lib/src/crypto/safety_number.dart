import 'dart:convert';
import 'dart:typed_data';
import 'package:crypto/crypto.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

const int signalFingerprintIterations = 5200;

class ContactVerificationRecord {
  final String contactId;
  final String safetyNumber;
  final int? verifiedAt;
  final String lastRemoteKeyHex;

  ContactVerificationRecord({
    required this.contactId,
    required this.safetyNumber,
    this.verifiedAt,
    required this.lastRemoteKeyHex,
  });

  Map<String, dynamic> toJson() => {
        'contactId': contactId,
        'safetyNumber': safetyNumber,
        'verifiedAt': verifiedAt,
        'lastRemoteKeyHex': lastRemoteKeyHex,
      };

  factory ContactVerificationRecord.fromJson(Map<String, dynamic> json) =>
      ContactVerificationRecord(
        contactId: json['contactId'] as String,
        safetyNumber: json['safetyNumber'] as String,
        verifiedAt: json['verifiedAt'] as int?,
        lastRemoteKeyHex: json['lastRemoteKeyHex'] as String,
      );
}

/// Safety Number Derivation Service (Signal Protocol Specification)
class SafetyNumberService {
  static const _storage = FlutterSecureStorage(
    aOptions: AndroidOptions(encryptedSharedPreferences: true),
    iOptions: IOSOptions(accessibility: KeychainAccessibility.first_unlock),
  );

  /// Computes the 30-digit fingerprint for an individual identity key.
  /// 5,200 SHA-512 iterations make key grinding computationally expensive.
  static String computeIndividualFingerprint(
    Uint8List identityKeyBytes,
    String identifier,
  ) {
    final idBytes = utf8.encode(identifier);

    // Initial round: SHA-512(identityKey || identifier)
    var digest = sha512.convert([...identityKeyBytes, ...idBytes]).bytes;

    // 5,200 iterations: digest = SHA-512(digest || identityKey)
    for (int i = 0; i < signalFingerprintIterations; i++) {
      digest = sha512.convert([...digest, ...identityKeyBytes]).bytes;
    }

    // Extract 6 groups of 5 digits from 4-byte big-endian chunks % 100,000
    final buffer = Uint8List.fromList(digest).buffer;
    final bdata = ByteData.view(buffer);
    final bufferString = StringBuffer();

    for (int i = 0; i < 6; i++) {
      final chunk = bdata.getUint32(i * 4, Endian.big);
      final fiveDigits = (chunk % 100000).toString().padLeft(5, '0');
      bufferString.write(fiveDigits);
    }

    return bufferString.toString();
  }

  /// Derives the 60-digit deterministic Safety Number for two parties.
  /// Returns 12 groups of 5 digits separated by spaces.
  static String generateCompositeSafetyNumber({
    required Uint8List localIdentityKey,
    required String localIdentifier,
    required Uint8List remoteIdentityKey,
    required String remoteIdentifier,
  }) {
    final fpA = computeIndividualFingerprint(localIdentityKey, localIdentifier);
    final fpB = computeIndividualFingerprint(remoteIdentityKey, remoteIdentifier);

    // Lexicographical sort ensures Alice and Bob compute the exact same ordering
    final sorted = [fpA, fpB]..sort();
    final combined = '${sorted[0]}${sorted[1]}';

    // Format as 12 groups of 5 digits
    final groups = <String>[];
    for (int i = 0; i < 12; i++) {
      groups.add(combined.substring(i * 5, i * 5 + 5));
    }

    return groups.join(' ');
  }

  /// Local Verification State Storage in FlutterSecureStorage
  static Future<ContactVerificationRecord?> getVerificationState(String contactId) async {
    final str = await _storage.read(key: 'verif_$contactId');
    if (str == null) return null;
    return ContactVerificationRecord.fromJson(jsonDecode(str));
  }

  static Future<void> saveVerificationState(ContactVerificationRecord record) async {
    await _storage.write(
      key: 'verif_${record.contactId}',
      value: jsonEncode(record.toJson()),
    );
  }

  /// Processes contact key update: detects key changes, resets verification, and returns new Safety Number.
  static Future<Map<String, dynamic>> processContactKey({
    required Uint8List localIdentityKey,
    required String localIdentifier,
    required String contactId,
    required Uint8List remoteKeyBytes,
  }) async {
    final remoteKeyHex = remoteKeyBytes
        .map((b) => b.toRadixString(16).padLeft(2, '0'))
        .join()
        .toUpperCase();

    final currentSafetyNumber = generateCompositeSafetyNumber(
      localIdentityKey: localIdentityKey,
      localIdentifier: localIdentifier,
      remoteIdentityKey: remoteKeyBytes,
      remoteIdentifier: contactId,
    );

    final existing = await getVerificationState(contactId);

    if (existing == null) {
      final newRecord = ContactVerificationRecord(
        contactId: contactId,
        safetyNumber: currentSafetyNumber,
        verifiedAt: null,
        lastRemoteKeyHex: remoteKeyHex,
      );
      await saveVerificationState(newRecord);
      return {
        'keyChanged': false,
        'safetyNumber': currentSafetyNumber,
        'isVerified': false,
      };
    }

    if (existing.lastRemoteKeyHex != remoteKeyHex) {
      // Key has changed! Reset verification and alert user
      final updated = ContactVerificationRecord(
        contactId: contactId,
        safetyNumber: currentSafetyNumber,
        verifiedAt: null, // Reset trust!
        lastRemoteKeyHex: remoteKeyHex,
      );
      await saveVerificationState(updated);
      return {
        'keyChanged': true,
        'safetyNumber': currentSafetyNumber,
        'isVerified': false,
      };
    }

    return {
      'keyChanged': false,
      'safetyNumber': existing.safetyNumber,
      'isVerified': existing.verifiedAt != null,
    };
  }

  static Future<void> markVerified(String contactId) async {
    final existing = await getVerificationState(contactId);
    if (existing != null) {
      final updated = ContactVerificationRecord(
        contactId: existing.contactId,
        safetyNumber: existing.safetyNumber,
        verifiedAt: DateTime.now().millisecondsSinceEpoch,
        lastRemoteKeyHex: existing.lastRemoteKeyHex,
      );
      await saveVerificationState(updated);
    }
  }
}

