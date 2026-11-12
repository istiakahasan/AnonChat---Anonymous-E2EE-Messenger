# AnonChat Native iOS (Swift & CryptoKit)

This module implements the native iOS client for AnonChat using **Apple CryptoKit**, **Apple Keychain Services**, and **SwiftUI**.

---

## 1. Cryptographic Primitives

- **Digital Signatures**: `Curve25519.Signing` (Ed25519)
- **Diffie-Hellman Key Agreement**: `Curve25519.KeyAgreement` (X25519)
- **Key Derivation**: `HKDF<SHA256>`
- **Symmetric Encryption**: `AES.GCM` (256-bit key, 96-bit nonce)
- **Hardware-Backed Key Storage**: Apple Keychain with `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` (Data Protection / Secure Enclave)
- **Safety Number**: 60-digit number derived using 5,200 iterations of SHA-512 over concatenated identity keys.

---

## 2. File Index

- [IdentityManager.swift](file:///E:/Projects/Anon_Chat/ios/AnonChat/Crypto/IdentityManager.swift) — Identity KeyPair, X25519 Signed PreKey, 100 OPKs, Keychain storage
- [X3DHProtocol.swift](file:///E:/Projects/Anon_Chat/ios/AnonChat/Crypto/X3DHProtocol.swift) — Extended Triple Diffie-Hellman key agreement
- [DoubleRatchetSession.swift](file:///E:/Projects/Anon_Chat/ios/AnonChat/Crypto/DoubleRatchetSession.swift) — Double Ratchet state machine with 4KB padding
- [SafetyNumber.swift](file:///E:/Projects/Anon_Chat/ios/AnonChat/Crypto/SafetyNumber.swift) — 60-digit Safety Number derivation with 5,200 SHA-512 iterations
- [TorManager.swift](file:///E:/Projects/Anon_Chat/ios/AnonChat/Network/TorManager.swift) — URLSession SOCKS5 proxy configuration
- [EncryptedDatabase.swift](file:///E:/Projects/Anon_Chat/ios/AnonChat/Storage/EncryptedDatabase.swift) — Local encrypted storage & TTL background purge worker
- [ContentView.swift](file:///E:/Projects/Anon_Chat/ios/AnonChat/UI/ContentView.swift) — SwiftUI Onboarding, Chat Timeline, and Safety Number views

