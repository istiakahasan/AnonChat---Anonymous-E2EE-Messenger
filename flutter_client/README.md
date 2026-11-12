# Flutter / Dart Integration with `libsignal`

This module provides the implementation of the **Signal Protocol** in **Flutter / Dart** using [`libsignal: ^2.3.0`](https://pub.dev/packages/libsignal) and [`flutter_secure_storage`](https://pub.dev/packages/flutter_secure_storage).

---

## 1. Installation

Add the packages to `pubspec.yaml`:

```yaml
dependencies:
  flutter:
    sdk: flutter
  libsignal: ^2.3.0
  flutter_secure_storage: ^9.0.0
```

Run:
```bash
flutter pub get
```

---

## 2. Architectural Highlights & Security Model

- **Flutter Rust Bridge (v2.0.0+)**: The `libsignal` Dart package is powered by `flutter_rust_bridge`. Memory allocations and deallocations for cryptographic handles (Curve25519 points, Kyber polynomials, AES contexts) are managed automatically by the underlying Rust engine.
- **Post-Quantum Cryptography (PQXDH)**: Supports **ML-KEM / Kyber-1024** PreKeys (`KyberKeyPair` and `KyberPreKeyRecord`) to defend against future quantum Harvest-Now-Decrypt-Later threats.
- **Hardware-Backed Key Storage (`FlutterSecureStorage`)**:
  - **Android**: `AndroidOptions(encryptedSharedPreferences: true)` using Android Keystore.
  - **iOS / macOS**: `IOSOptions(accessibility: KeychainAccessibility.first_unlock)` using the Apple Keychain.
- **Sealed Sender (`SealedSessionCipher`)**: Protects metadata and guarantees sender anonymity; the relay server cannot identify the sender.
- **Web Support**: Web support via WASM (`libsignal` compiled to WebAssembly) is available but should be treated as **experimental**.

---

## 3. Protocol Lifecycle Implementation

### Step 2: Initialize Library
```dart
import 'package:libsignal/libsignal.dart';

// Initializes the native Rust bridge
await LibSignal.init();
```

### Step 3: Generate Identity Key Pair
```dart
final identity = IdentityKeyPair.generate();
```

### Step 4: Generate PreKeys
```dart
final preKeyPrivate = PrivateKey.generate();
final preKeyPublic = preKeyPrivate.getPublicKey();
final preKey = PreKeyRecord(
  id: 1,
  publicKey: preKeyPublic,
  privateKey: preKeyPrivate,
);
```

### Step 5: Generate Signed PreKey
```dart
final signedPreKeyPrivate = PrivateKey.generate();
final signedPreKeyPublic = signedPreKeyPrivate.getPublicKey();
final identityPrivate = PrivateKey.deserialize(bytes: identity.privateKey.toList());

// Sign SPK public key with Ed25519 identity key
final signature = identityPrivate.sign(message: signedPreKeyPublic.serialize().toList());

final signedPreKey = SignedPreKeyRecord(
  id: 1,
  timestamp: BigInt.from(DateTime.now().millisecondsSinceEpoch),
  publicKey: signedPreKeyPublic,
  privateKey: signedPreKeyPrivate,
  signature: signature.toList(),
);
```

### Step 6: Generate Post-Quantum Kyber PreKey
```dart
final kyberKeyPair = KyberKeyPair.generate();
final kyberSignature = identityPrivate.sign(
  message: kyberKeyPair.getPublicKey().serialize().toList(),
);

final kyberPreKey = KyberPreKeyRecord.create(
  id: BigInt.from(DateTime.now().millisecondsSinceEpoch),
  keyPair: kyberKeyPair,
  signature: kyberSignature.toList(),
);
```

### Step 7: Session Establishment
```dart
final sessionStore = InMemorySessionStore();
final identityStore = InMemoryIdentityKeyStore(identity, registrationId);

final builder = SessionBuilder(
  sessionStore: sessionStore,
  identityKeyStore: identityStore,
);

await builder.processPreKeyBundle(recipientAddress, preKeyBundle);
```

### Step 8: Encrypt / Decrypt
```dart
final cipher = SessionCipher(
  sessionStore: sessionStore,
  identityKeyStore: identityStore,
);

// Encrypt outbound plaintext
final encrypted = await cipher.encrypt(recipientAddress, plaintext);

// Decrypt inbound ciphertext
final decrypted = await cipher.decrypt(senderAddress, ciphertext);
```

### Step 9: Sealed Sender (Anonymity)
```dart
final sealedCipher = SealedSessionCipher(
  sessionStore: sessionStore,
  identityKeyStore: identityStore,
  signedPreKeyStore: signedPreKeyStore,
  kyberPreKeyStore: kyberPreKeyStore,
);

// Requires a server-issued SenderCertificate
final sealed = await sealedCipher.encrypt(
  recipientAddress,
  plaintext,
  senderCert,
  contentHint: ContentHint.resendable,
);

// Decrypt anonymous sealed payload
final decryptedPlaintext = await sealedCipher.decrypt(senderCert, sealed);
```

---

## 4. Key-Change Detection & Safety Numbers

Before any session establishment or encryption, the recipient's public key fingerprint is cross-referenced with `SecureKeyStore`. If a previously verified contact's key differs, a `KeyChangeException` is thrown:

```dart
try {
  await signalService.establishSession(
    recipientAddress: recipient,
    preKeyBundle: bundle,
  );
} on KeyChangeException catch (e) {
  // Outbound messages are BLOCKED until the user approves the new Safety Number
  showKeyChangeWarningDialog(e);
}
```

---

## 5. File Index

- [pubspec.yaml](file:///E:/Projects/Anon_Chat/flutter_client/pubspec.yaml) — Package configuration
- [signal_service.dart](file:///E:/Projects/Anon_Chat/flutter_client/lib/src/crypto/signal_service.dart) — Full protocol implementation with Kyber & Sealed Sender
- [secure_key_store.dart](file:///E:/Projects/Anon_Chat/flutter_client/lib/src/storage/secure_key_store.dart) — `FlutterSecureStorage` hardware persistence
- [chat_screen.dart](file:///E:/Projects/Anon_Chat/flutter_client/lib/src/ui/chat_screen.dart) — Flutter UI screen with Sealed Sender switch
- [anonchat_flutter.dart](file:///E:/Projects/Anon_Chat/flutter_client/lib/anonchat_flutter.dart) — Library export

