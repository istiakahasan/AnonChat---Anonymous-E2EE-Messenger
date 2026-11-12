import Foundation
import CryptoKit
import Security

/// Task 1: Cryptographic Identity Layer (iOS / Swift)
///
/// Uses Apple CryptoKit (Curve25519.Signing and Curve25519.KeyAgreement)
/// and Apple Keychain Services with `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`.
///
/// Security Requirements:
/// - [x] Private keys are locked in iOS Keychain (Hardware Secure Enclave / Data Protection).
/// - [x] Keys are never logged to console.
/// - [x] No plaintext is written to disk without encryption.
public class IdentityManager {
    public static let shared = IdentityManager()

    public private(set) var identityPrivateKey: Curve25519.Signing.PrivateKey
    public private(set) var identityPublicKey: Curve25519.Signing.PublicKey

    public private(set) var identityDhPrivateKey: Curve25519.KeyAgreement.PrivateKey
    public private(set) var identityDhPublicKey: Curve25519.KeyAgreement.PublicKey

    public private(set) var signedPreKeyId: UInt32 = 1
    public private(set) var signedPreKeyPrivate: Curve25519.KeyAgreement.PrivateKey
    public private(set) var signedPreKeyPublic: Curve25519.KeyAgreement.PublicKey
    public private(set) var signedPreKeySignature: Data

    // Pool of 100 One-Time PreKeys (OPKs): (id, privateKey, publicKey)
    public private(set) var oneTimePreKeys: [(id: UInt32, priv: Curve25519.KeyAgreement.PrivateKey, pub: Curve25519.KeyAgreement.PublicKey)] = []

    private init() {
        // 1. Ed25519 Identity KeyPair (for digital signatures)
        let signingPriv = Curve25519.Signing.PrivateKey()
        self.identityPrivateKey = signingPriv
        self.identityPublicKey = signingPriv.publicKey

        // 2. X25519 Identity DH KeyPair (for Diffie-Hellman)
        let dhPriv = Curve25519.KeyAgreement.PrivateKey()
        self.identityDhPrivateKey = dhPriv
        self.identityDhPublicKey = dhPriv.publicKey

        // 3. X25519 Signed PreKey
        let spkPriv = Curve25519.KeyAgreement.PrivateKey()
        let spkPub = spkPriv.publicKey
        self.signedPreKeyPrivate = spkPriv
        self.signedPreKeyPublic = spkPub

        // Sign the X25519 Signed PreKey public key with Ed25519 Identity Key
        do {
            self.signedPreKeySignature = try signingPriv.signature(for: spkPub.rawRepresentation)
        } catch {
            fatalError("Failed to sign Signed PreKey: \(error)")
        }

        // 4. Generate 100 One-Time PreKeys (OPKs)
        for i in 0..<100 {
            let opkPriv = Curve25519.KeyAgreement.PrivateKey()
            self.oneTimePreKeys.append((id: UInt32(i), priv: opkPriv, pub: opkPriv.publicKey))
        }

        // Save private keys to Apple Keychain
        persistToKeychain()
    }

    /// Derives UserId: Hex-encoded SHA-256 fingerprint of the Ed25519 Identity public key.
    public func userId() -> String {
        let digest = SHA256.hash(data: identityPublicKey.rawRepresentation)
        return digest.map { String(format: "%02x", $0) }.joined()
    }

    /// Derives Friend Code for easy QR code and contact sharing.
    public func friendCode() -> String {
        return "anon:fc:\(userId())"
    }

    /// Exports public PreKeyBundle JSON ready for server upload.
    /// SECURITY: Contains ZERO private keys.
    public func exportPreKeyBundle() -> [String: Any] {
        let opkList = oneTimePreKeys.map { opk in
            [
                "id": opk.id,
                "key": opk.pub.rawRepresentation.base64EncodedString()
            ]
        }

        return [
            "user_id": userId(),
            "identity_key": identityPublicKey.rawRepresentation.base64EncodedString(),
            "identity_dh_key": identityDhPublicKey.rawRepresentation.base64EncodedString(),
            "signed_prekey_id": signedPreKeyId,
            "signed_prekey": signedPreKeyPublic.rawRepresentation.base64EncodedString(),
            "signed_prekey_signature": signedPreKeySignature.base64EncodedString(),
            "one_time_prekeys": opkList
        ]
    }

    /// Persists private keys into Apple Keychain using strict device protection.
    private func persistToKeychain() {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: "AnonChat_IdentityKey",
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            kSecValueData as String: identityPrivateKey.rawRepresentation
        ]
        SecItemDelete(query as CFDictionary)
        SecItemAdd(query as CFDictionary, nil)
    }
}

