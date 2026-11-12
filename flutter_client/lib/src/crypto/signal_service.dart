import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';
import 'package:libsignal/libsignal.dart';
import '../storage/secure_key_store.dart';

/// Custom Exception thrown when a contact's Safety Number / Identity Key changes.
class KeyChangeException implements Exception {
  final String contactName;
  final String oldFingerprint;
  final String newFingerprint;

  KeyChangeException({
    required this.contactName,
    required this.oldFingerprint,
    required this.newFingerprint,
  });

  @override
  String toString() =>
      'KeyChangeException: Safety code changed for $contactName! Outbound messages blocked.';
}

/// Core Signal Protocol Engine in Flutter / Dart
///
/// Features:
/// - LibSignal.init() with Flutter Rust Bridge (automated memory management)
/// - Ed25519 Identity Key Pair
/// - X25519 PreKeys + Signed PreKeys
/// - Post-Quantum Kyber PreKeys (KyberKeyPair & KyberPreKeyRecord)
/// - SessionBuilder & SessionCipher
/// - SealedSessionCipher for Anonymous Sender delivery (Sealed Sender)
/// - Key-Change Detection (Safety Numbers)
/// - FlutterSecureStorage hardware-backed persistence
class FlutterSignalService {
  static FlutterSignalService? _instance;
  bool _isInitialized = false;

  late IdentityKeyPair _identity;
  late int _registrationId;
  late SignedPreKeyRecord _signedPreKey;
  late KyberPreKeyRecord _kyberPreKey;
  final List<PreKeyRecord> _preKeys = [];

  // Stores
  late InMemorySessionStore _sessionStore;
  late InMemoryIdentityKeyStore _identityStore;
  late InMemoryPreKeyStore _preKeyStore;
  late InMemorySignedPreKeyStore _signedPreKeyStore;
  late InMemoryKyberPreKeyStore _kyberPreKeyStore;

  FlutterSignalService._();

  static FlutterSignalService get instance =>
      _instance ??= FlutterSignalService._();

  bool get isInitialized => _isInitialized;
  IdentityKeyPair get identity => _identity;
  int get registrationId => _registrationId;

  /// Step 2: Initialize Library (Flutter Rust Bridge)
  /// Initializes native Rust bindings and bootstraps or recovers identity from SecureStorage.
  Future<void> initialize() async {
    if (_isInitialized) return;

    // 1. Initialize native LibSignal Rust Bridge
    // Memory is managed automatically by Rust via Flutter Rust Bridge in v2.0.0+
    await LibSignal.init();

    // 2. Attempt to load existing identity from FlutterSecureStorage
    final savedIdentity = await SecureKeyStore.loadIdentityKeyPair();
    final savedRegId = await SecureKeyStore.loadRegistrationId();
    final savedSpk = await SecureKeyStore.loadSignedPreKeyRecord();
    final savedKyber = await SecureKeyStore.loadKyberPreKeyRecord();

    if (savedIdentity != null && savedRegId != null && savedSpk != null && savedKyber != null) {
      _identity = savedIdentity;
      _registrationId = savedRegId;
      _signedPreKey = savedSpk;
      _kyberPreKey = savedKyber;
    } else {
      // Step 3: Generate Identity Key Pair (One-time per device)
      _identity = IdentityKeyPair.generate();
      _registrationId = _generateRegistrationId();

      // Step 5: Generate Signed PreKey
      final signedPreKeyPrivate = PrivateKey.generate();
      final signedPreKeyPublic = signedPreKeyPrivate.getPublicKey();
      final identityPrivate = PrivateKey.deserialize(bytes: _identity.privateKey.toList());
      final signature = identityPrivate.sign(message: signedPreKeyPublic.serialize().toList());

      _signedPreKey = SignedPreKeyRecord(
        id: 1,
        timestamp: BigInt.from(DateTime.now().millisecondsSinceEpoch),
        publicKey: signedPreKeyPublic,
        privateKey: signedPreKeyPrivate,
        signature: signature.toList(),
      );

      // Step 6: Generate Kyber PreKey (Post-Quantum)
      final kyberKeyPair = KyberKeyPair.generate();
      final kyberSignature = identityPrivate.sign(
        message: kyberKeyPair.getPublicKey().serialize().toList(),
      );

      _kyberPreKey = KyberPreKeyRecord.create(
        id: BigInt.from(DateTime.now().millisecondsSinceEpoch),
        keyPair: kyberKeyPair,
        signature: kyberSignature.toList(),
      );

      // Persist to FlutterSecureStorage
      await SecureKeyStore.saveIdentityKeyPair(_identity);
      await SecureKeyStore.saveRegistrationId(_registrationId);
      await SecureKeyStore.saveSignedPreKeyRecord(_signedPreKey);
      await SecureKeyStore.saveKyberPreKeyRecord(_kyberPreKey);
    }

    // Step 4: Generate Pool of 100 One-Time PreKeys
    _preKeys.clear();
    for (int i = 1; i <= 100; i++) {
      final preKeyPrivate = PrivateKey.generate();
      final preKeyPublic = preKeyPrivate.getPublicKey();
      final preKey = PreKeyRecord(id: i, publicKey: preKeyPublic, privateKey: preKeyPrivate);
      _preKeys.add(preKey);
    }

    // Initialize stores
    _sessionStore = InMemorySessionStore();
    _identityStore = InMemoryIdentityKeyStore(_identity, _registrationId);
    _preKeyStore = InMemoryPreKeyStore();
    _signedPreKeyStore = InMemorySignedPreKeyStore();
    _kyberPreKeyStore = InMemoryKyberPreKeyStore();

    for (final pk in _preKeys) {
      await _preKeyStore.storePreKey(pk.id, pk);
    }
    await _signedPreKeyStore.storeSignedPreKey(_signedPreKey.id, _signedPreKey);
    await _kyberPreKeyStore.storeKyberPreKey(_kyberPreKey.id, _kyberPreKey);

    _isInitialized = true;
  }

  /// Exports public keys bundle for the server.
  /// SECURITY: Contains ZERO private keys.
  Map<String, dynamic> exportPublicPreKeyBundle() {
    return {
      'registrationId': _registrationId,
      'identityKey': base64Encode(_identity.publicKey.serialize().toList()),
      'signedPreKey': {
        'id': _signedPreKey.id,
        'publicKey': base64Encode(_signedPreKey.publicKey.serialize().toList()),
        'signature': base64Encode(_signedPreKey.signature),
      },
      'kyberPreKey': {
        'id': _kyberPreKey.id.toString(),
        'publicKey': base64Encode(_kyberPreKey.keyPair.getPublicKey().serialize().toList()),
        'signature': base64Encode(_kyberPreKey.signature),
      },
      'preKeys': _preKeys
          .map((k) => {
                'id': k.id,
                'publicKey': base64Encode(k.publicKey.serialize().toList()),
              })
          .toList(),
    };
  }

  /// Step 7: Session Establishment with Recipient
  /// Enforces Key-Change detection before accepting bundle.
  Future<void> establishSession({
    required ProtocolAddress recipientAddress,
    required PreKeyBundle preKeyBundle,
  }) async {
    _ensureReady();

    // Verify recipient Identity Key / Safety Number
    final recipientKeyHex = _formatKeyFingerprint(preKeyBundle.identityKey);
    final trustedContacts = await SecureKeyStore.getTrustedContactsMap();
    final previousFingerprint = trustedContacts[recipientAddress.name];

    if (previousFingerprint != null && previousFingerprint != recipientKeyHex) {
      // SECURITY: Block communication immediately if safety number changed
      throw KeyChangeException(
        contactName: recipientAddress.name,
        oldFingerprint: previousFingerprint,
        newFingerprint: recipientKeyHex,
      );
    }

    // Trust and store new contact key
    if (previousFingerprint == null) {
      await SecureKeyStore.saveTrustedContact(recipientAddress.name, recipientKeyHex);
    }

    final builder = SessionBuilder(
      sessionStore: _sessionStore,
      identityKeyStore: _identityStore,
    );

    await builder.processPreKeyBundle(recipientAddress, preKeyBundle);
  }

  /// Explicitly approves a contact's changed safety number after user confirmation.
  Future<void> approveContactKeyChange({
    required String contactName,
    required String newFingerprint,
  }) async {
    await SecureKeyStore.saveTrustedContact(contactName, newFingerprint);
  }

  /// Step 8: Standard Encrypt
  Future<CiphertextMessage> encrypt({
    required ProtocolAddress recipientAddress,
    required Uint8Array plaintext,
  }) async {
    _ensureReady();
    final cipher = SessionCipher(
      sessionStore: _sessionStore,
      identityKeyStore: _identityStore,
    );
    return await cipher.encrypt(recipientAddress, plaintext);
  }

  /// Step 8: Standard Decrypt
  Future<Uint8Array> decrypt({
    required ProtocolAddress senderAddress,
    required PreKeySignalMessage ciphertext,
  }) async {
    _ensureReady();
    final cipher = SessionCipher(
      sessionStore: _sessionStore,
      identityKeyStore: _identityStore,
    );
    return await cipher.decrypt(senderAddress, ciphertext);
  }

  /// Step 9: Sealed Sender (Anonymity)
  /// Encrypts a message such that the server cannot learn who the sender is.
  /// Requires a valid server-issued SenderCertificate.
  Future<Uint8Array> encryptSealedSender({
    required ProtocolAddress recipientAddress,
    required Uint8Array plaintext,
    required SenderCertificate senderCertificate,
    ContentHint contentHint = ContentHint.resendable,
  }) async {
    _ensureReady();

    final sealedCipher = SealedSessionCipher(
      sessionStore: _sessionStore,
      identityKeyStore: _identityStore,
      signedPreKeyStore: _signedPreKeyStore,
      kyberPreKeyStore: _kyberPreKeyStore,
    );

    return await sealedCipher.encrypt(
      recipientAddress,
      plaintext,
      senderCertificate,
      contentHint: contentHint,
    );
  }

  /// Step 9: Sealed Sender Decrypt
  /// Decrypts incoming anonymous sealed sender ciphertext.
  Future<Uint8Array> decryptSealedSender({
    required SenderCertificate senderCertificate,
    required Uint8Array sealedCiphertext,
  }) async {
    _ensureReady();

    final sealedCipher = SealedSessionCipher(
      sessionStore: _sessionStore,
      identityKeyStore: _identityStore,
      signedPreKeyStore: _signedPreKeyStore,
      kyberPreKeyStore: _kyberPreKeyStore,
    );

    return await sealedCipher.decrypt(senderCertificate, sealedCiphertext);
  }

  void _ensureReady() {
    if (!_isInitialized) {
      throw StateError('FlutterSignalService has not been initialized. Call initialize() first.');
    }
  }

  int _generateRegistrationId() {
    final rand = Random.secure();
    return rand.nextInt(16380) + 1;
  }

  String _formatKeyFingerprint(PublicKey key) {
    final bytes = key.serialize();
    final hexStr = bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
    return hexStr.toUpperCase();
  }
}

