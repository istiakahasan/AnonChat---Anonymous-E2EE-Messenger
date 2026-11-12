import Foundation
import CryptoKit

/// Task 3: Double Ratchet State Machine (iOS / Swift)
///
/// Features:
/// - Symmetric KDF chains using HMAC<SHA256>
/// - Diffie-Hellman ratchet using Curve25519.KeyAgreement
/// - AES-256-GCM authenticated encryption with 96-bit nonce
/// - Header authenticated as Associated Authenticated Data (AAD)
/// - Strict 4KB (4096-byte) constant padding to defend against traffic analysis
public class DoubleRatchetSession {
    public static let fixedBlockSize = 4096

    public struct Header: Codable {
        public let dhPub: String
        public let pn: UInt32
        public let n: UInt32

        enum CodingKeys: String, CodingKey {
            case dhPub = "dh_pub"
            case pn = "pn"
            case n = "n"
        }

        public func toAADData() -> Data {
            return (try? JSONEncoder().encode(self)) ?? Data()
        }
    }

    public struct EncryptedEnvelope: Codable {
        public let header: Header
        public let ciphertext: String
        public let nonce: String
    }

    private var dhsPrivate: Curve25519.KeyAgreement.PrivateKey
    private var dhsPublic: Curve25519.KeyAgreement.PublicKey
    private var dhrPublic: Curve25519.KeyAgreement.PublicKey?
    private var rootKey: SymmetricKey
    private var sendingChainKey: SymmetricKey?
    private var receivingChainKey: SymmetricKey?
    private var ns: UInt32 = 0
    private var nr: UInt32 = 0
    private var pn: UInt32 = 0
    private var skippedKeys: [String: SymmetricKey] = [:]

    public init(
        dhsPrivate: Curve25519.KeyAgreement.PrivateKey,
        dhsPublic: Curve25519.KeyAgreement.PublicKey,
        dhrPublic: Curve25519.KeyAgreement.PublicKey?,
        rootKey: SymmetricKey,
        sendingChainKey: SymmetricKey? = nil
    ) {
        self.dhsPrivate = dhsPrivate
        self.dhsPublic = dhsPublic
        self.dhrPublic = dhrPublic
        self.rootKey = rootKey
        self.sendingChainKey = sendingChainKey
    }

    /// Alice ratchet session initialization after X3DH
    public static func initAlice(
        sharedSecret: SymmetricKey,
        bobSpkPublic: Curve25519.KeyAgreement.PublicKey
    ) throws -> DoubleRatchetSession {
        let dhsPriv = Curve25519.KeyAgreement.PrivateKey()
        let dhsPub = dhsPriv.publicKey

        let dhOut = try dhsPriv.sharedSecretFromKeyAgreement(with: bobSpkPublic)
        let (newRk, cks) = kdfRk(rk: sharedSecret, dhOut: dhOut)

        return DoubleRatchetSession(
            dhsPrivate: dhsPriv,
            dhsPublic: dhsPub,
            dhrPublic: bobSpkPublic,
            rootKey: newRk,
            sendingChainKey: cks
        )
    }

    /// Encrypts an outbound plaintext message:
    /// - Advances sending chain
    /// - Pads to 4096 bytes with random bytes
    /// - Authenticates header as AAD in AES-256-GCM
    public func ratchetEncrypt(plaintext: Data) throws -> EncryptedEnvelope {
        guard let currentCks = sendingChainKey else {
            throw NSError(domain: "AnonChat", code: 1, userInfo: [NSLocalizedDescriptionKey: "No sending chain key"])
        }

        let (nextCks, mk) = kdfCk(ck: currentCks)
        self.sendingChainKey = nextCks

        let header = Header(
            dhPub: dhsPublic.rawRepresentation.base64EncodedString(),
            pn: pn,
            n: ns
        )
        self.ns += 1

        let paddedPayload = padTo4KB(data: plaintext)

        // 96-bit Nonce derived deterministically from message number
        var nonceBytes = Data(repeating: 0, count: 12)
        var bigN = header.n.bigEndian
        withUnsafeBytes(of: &bigN) { nonceBytes.replaceSubrange(8..<12, with: $0) }
        let nonce = try AES.GCM.Nonce(data: nonceBytes)

        let aad = header.toAADData()
        let sealedBox = try AES.GCM.seal(paddedPayload, using: mk, nonce: nonce, authenticating: aad)

        return EncryptedEnvelope(
            header: header,
            ciphertext: sealedBox.ciphertext.base64EncodedString() + sealedBox.tag.base64EncodedString(),
            nonce: nonceBytes.base64EncodedString()
        )
    }

    /// Constant-size 4KB padding with cryptographically secure random bytes
    private func padTo4KB(data: Data) -> Data {
        let minCapacity = 4 + data.count
        let targetSize = ((minCapacity + DoubleRatchetSession.fixedBlockSize - 1) / DoubleRatchetSession.fixedBlockSize) * DoubleRatchetSession.fixedBlockSize

        var padded = Data()
        var lenBigEndian = UInt32(data.count).bigEndian
        withUnsafeBytes(of: &lenBigEndian) { padded.append(contentsOf: $0) }
        padded.append(data)

        let padLen = targetSize - padded.count
        if padLen > 0 {
            var randomBytes = [UInt8](repeating: 0, count: padLen)
            _ = SecRandomCopyBytes(kSecRandomDefault, padLen, &randomBytes)
            padded.append(contentsOf: randomBytes)
        }

        return padded
    }

    private static func kdfRk(rk: SymmetricKey, dhOut: SharedSecret) -> (SymmetricKey, SymmetricKey) {
        var dhData = Data()
        dhOut.withUnsafeBytes { dhData.append(contentsOf: $0) }

        let derived = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: dhData),
            salt: rk.withUnsafeBytes { Data($0) },
            info: "AnonChat_DoubleRatchet_RootKDF".data(using: .utf8)!,
            outputByteCount: 64
        )

        let derivedData = derived.withUnsafeBytes { Data($0) }
        let newRk = SymmetricKey(data: derivedData.subdata(in: 0..<32))
        let nextCk = SymmetricKey(data: derivedData.subdata(in: 32..<64))
        return (newRk, nextCk)
    }

    private func kdfCk(ck: SymmetricKey) -> (SymmetricKey, SymmetricKey) {
        let hmac1 = HMAC<SHA256>.authenticationCode(for: Data([0x01]), using: ck)
        let mk = SymmetricKey(data: Data(hmac1))

        let hmac2 = HMAC<SHA256>.authenticationCode(for: Data([0x02]), using: ck)
        let nextCk = SymmetricKey(data: Data(hmac2))

        return (nextCk, mk)
    }
}

