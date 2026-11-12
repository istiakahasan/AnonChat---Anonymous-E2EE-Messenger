import 'dart:convert';
import 'dart:typed_data';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:libsignal/libsignal.dart';

/// Secure Storage wrapper using FlutterSecureStorage for hardware-backed key persistence.
///
/// Security Requirements:
/// - Private keys are encrypted using hardware-backed keystores (Android Keystore / iOS Keychain).
/// - EncryptedSharedPreferences enabled on Android.
/// - KeychainAccessibility.first_unlock enabled on iOS.
class SecureKeyStore {
  static const _storage = FlutterSecureStorage(
    aOptions: AndroidOptions(encryptedSharedPreferences: true),
    iOptions: IOSOptions(accessibility: KeychainAccessibility.first_unlock),
  );

  static const _keyIdentityPrivate = 'libsignal_identity_private';
  static const _keyIdentityPublic = 'libsignal_identity_public';
  static const _keyRegistrationId = 'libsignal_registration_id';
  static const _keySignedPreKey = 'libsignal_signed_prekey';
  static const _keyKyberPreKey = 'libsignal_kyber_prekey';
  static const _keyTrustedContacts = 'libsignal_trusted_contacts';

  /// Saves the Identity Key Pair securely.
  static async Future<void> saveIdentityKeyPair(IdentityKeyPair identity) async {
    final privB64 = base64Encode(identity.privateKey.toList());
    final pubB64 = base64Encode(identity.publicKey.serialize().toList());

    await _storage.write(key: _keyIdentityPrivate, value: privB64);
    await _storage.write(key: _keyIdentityPublic, value: pubB64);
  }

  /// Loads the saved Identity Key Pair, or null if not yet generated.
  static async Future<IdentityKeyPair?> loadIdentityKeyPair() async {
    final privB64 = await _storage.read(key: _keyIdentityPrivate);
    final pubB64 = await _storage.read(key: _keyIdentityPublic);

    if (privB64 == null || pubB64 == null) return null;

    final privBytes = base64Decode(privB64);
    final pubBytes = base64Decode(pubB64);

    final privateKey = PrivateKey.deserialize(bytes: privBytes);
    final publicKey = PublicKey.deserialize(bytes: pubBytes);

    return IdentityKeyPair(publicKey: publicKey, privateKey: privateKey);
  }

  /// Saves Registration ID.
  static async Future<void> saveRegistrationId(int registrationId) async {
    await _storage.write(key: _keyRegistrationId, value: registrationId.toString());
  }

  /// Loads Registration ID.
  static async Future<int?> loadRegistrationId() async {
    final str = await _storage.read(key: _keyRegistrationId);
    return str != null ? int.tryParse(str) : null;
  }

  /// Saves Signed PreKey Record bytes.
  static async Future<void> saveSignedPreKeyRecord(SignedPreKeyRecord record) async {
    final b64 = base64Encode(record.serialize().toList());
    await _storage.write(key: _keySignedPreKey, value: b64);
  }

  /// Loads Signed PreKey Record.
  static async Future<SignedPreKeyRecord?> loadSignedPreKeyRecord() async {
    final b64 = await _storage.read(key: _keySignedPreKey);
    if (b64 == null) return null;
    final bytes = base64Decode(b64);
    return SignedPreKeyRecord.deserialize(bytes: bytes);
  }

  /// Saves Kyber PreKey Record (Post-Quantum).
  static async Future<void> saveKyberPreKeyRecord(KyberPreKeyRecord record) async {
    final b64 = base64Encode(record.serialize().toList());
    await _storage.write(key: _keyKyberPreKey, value: b64);
  }

  /// Loads Kyber PreKey Record (Post-Quantum).
  static async Future<KyberPreKeyRecord?> loadKyberPreKeyRecord() async {
    final b64 = await _storage.read(key: _keyKyberPreKey);
    if (b64 == null) return null;
    final bytes = base64Decode(b64);
    return KyberPreKeyRecord.deserialize(bytes: bytes);
  }

  /// Gets contact identity fingerprints map: Map<String, String> (contactName -> hexFingerprint).
  static async Future<Map<String, String>> getTrustedContactsMap() async {
    final jsonStr = await _storage.read(key: _keyTrustedContacts);
    if (jsonStr == null) return {};
    try {
      final decoded = jsonDecode(jsonStr);
      return Map<String, String>.from(decoded);
    } catch (_) {
      return {};
    }
  }

  /// Saves contact identity fingerprint for key-change detection.
  static async Future<void> saveTrustedContact(String contactName, String fingerprint) async {
    final map = await getTrustedContactsMap();
    map[contactName] = fingerprint;
    await _storage.write(key: _keyTrustedContacts, value: jsonEncode(map));
  }

  /// Completely wipes all keys from secure storage (e.g. self-destruct).
  static async Future<void> clearAll() async {
    await _storage.deleteAll();
  }
}

