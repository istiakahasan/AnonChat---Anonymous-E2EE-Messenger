import Foundation
import CryptoKit

/// Task 2: X3DH Key Agreement (iOS / Swift)
///
/// Features:
/// - Alice verifies Bob's signature on his Signed PreKey using CryptoKit Ed25519.
/// - Performs DH1, DH2, DH3, and optional DH4 using Curve25519.KeyAgreement.
/// - Derives identical 256-bit SharedSecret via HKDF-SHA256.
/// - Formats first-message X3DHInitiation envelope.
public enum X3DHError: Error {
    case invalidSignature
    case invalidKeyLength
    case opkNotFound
    case kdfFailed
}

public struct X3DHInitiation: Codable {
    public let aliceIdentityKey: String
    public let aliceIdentityDhKey: String
    public let aliceEphemeralKey: String
    public let signedPreKeyId: UInt32
    public let oneTimePreKeyId: UInt32?

    enum CodingKeys: String, CodingKey {
        case aliceIdentityKey = "alice_identity_key"
        case aliceIdentityDhKey = "alice_identity_dh_key"
        case aliceEphemeralKey = "alice_ephemeral_key"
        case signedPreKeyId = "signed_prekey_id"
        case oneTimePreKeyId = "one_time_prekey_id"
    }
}

public class X3DHProtocol {
    private static let infoData = "AnonChat_X3DH_v1_Protocol".data(using: .utf8)!

    /// Alice initiates X3DH with Bob's PreKeyBundle
    public static func aliceInitiate(
        aliceManager: IdentityManager,
        bobBundle: [String: Any]
    ) throws -> (sharedSecret: SymmetricKey, initiation: X3DHInitiation) {
        // 1. Decode Bob's public keys
        guard let bobIkB64 = bobBundle["identity_key"] as? String,
              let bobIkData = Data(base64Encoded: bobIkB64),
              let bobIk = try? Curve25519.Signing.PublicKey(rawRepresentation: bobIkData),
              let bobIkDhB64 = bobBundle["identity_dh_key"] as? String,
              let bobIkDhData = Data(base64Encoded: bobIkDhB64),
              let bobIkDh = try? Curve25519.KeyAgreement.PublicKey(rawRepresentation: bobIkDhData),
              let bobSpkB64 = bobBundle["signed_prekey"] as? String,
              let bobSpkData = Data(base64Encoded: bobSpkB64),
              let bobSpk = try? Curve25519.KeyAgreement.PublicKey(rawRepresentation: bobSpkData),
              let sigB64 = bobBundle["signed_prekey_signature"] as? String,
              let sigData = Data(base64Encoded: sigB64) else {
            throw X3DHError.invalidKeyLength
        }

        // 2. Alice verifies Bob's signature on his Signed PreKey
        guard bobIk.isValidSignature(sigData, for: bobSpk.rawRepresentation) else {
            throw X3DHError.invalidSignature
        }

        // 3. Generate Alice's ephemeral keypair (EK_A)
        let aliceEkPriv = Curve25519.KeyAgreement.PrivateKey()
        let aliceEkPub = aliceEkPriv.publicKey

        // 4. Perform Diffie-Hellman:
        // DH1 = X25519(IK_A_dh_priv, SPK_B_pub)
        let dh1 = try aliceManager.identityDhPrivateKey.sharedSecretFromKeyAgreement(with: bobSpk)
        // DH2 = X25519(EK_A_priv, IK_B_dh_pub)
        let dh2 = try aliceEkPriv.sharedSecretFromKeyAgreement(with: bobIkDh)
        // DH3 = X25519(EK_A_priv, SPK_B_pub)
        let dh3 = try aliceEkPriv.sharedSecretFromKeyAgreement(with: bobSpk)

        // DH4 = X25519(EK_A_priv, OPK_B_pub) [if OPK present]
        var usedOpkId: UInt32? = nil
        var kmData = Data()
        dh1.withUnsafeBytes { kmData.append(contentsOf: $0) }
        dh2.withUnsafeBytes { kmData.append(contentsOf: $0) }
        dh3.withUnsafeBytes { kmData.append(contentsOf: $0) }

        if let opkList = bobBundle["one_time_prekeys"] as? [[String: Any]],
           let firstOpk = opkList.first,
           let opkId = firstOpk["id"] as? UInt32,
           let opkB64 = firstOpk["key"] as? String,
           let opkData = Data(base64Encoded: opkB64),
           let bobOpk = try? Curve25519.KeyAgreement.PublicKey(rawRepresentation: opkData) {
            let dh4 = try aliceEkPriv.sharedSecretFromKeyAgreement(with: bobOpk)
            dh4.withUnsafeBytes { kmData.append(contentsOf: $0) }
            usedOpkId = opkId
        }

        // 5. Derive SharedSecret via HKDF-SHA256
        let salt = Data(repeating: 0, count: 32)
        let sharedSecret = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: kmData),
            salt: salt,
            info: infoData,
            outputByteCount: 32
        )

        let spkId = (bobBundle["signed_prekey_id"] as? UInt32) ?? 1
        let initiation = X3DHInitiation(
            aliceIdentityKey: aliceManager.identityPublicKey.rawRepresentation.base64EncodedString(),
            aliceIdentityDhKey: aliceManager.identityDhPublicKey.rawRepresentation.base64EncodedString(),
            aliceEphemeralKey: aliceEkPub.rawRepresentation.base64EncodedString(),
            signedPreKeyId: spkId,
            oneTimePreKeyId: usedOpkId
        )

        return (sharedSecret, initiation)
    }
}

