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
    public var bobFirstMessage: Bool = false

    public init(
        dhsPrivate: Curve25519.KeyAgreement.PrivateKey,
        dhsPublic: Curve25519.KeyAgreement.PublicKey,
        dhrPublic: Curve25519.KeyAgreement.PublicKey?,
        rootKey: SymmetricKey,
        sendingChainKey: SymmetricKey? = nil,
        receivingChainKey: SymmetricKey? = nil,
        bobFirstMessage: Bool = false
    ) {
        self.dhsPrivate = dhsPrivate
        self.dhsPublic = dhsPublic
        self.dhrPublic = dhrPublic
        self.rootKey = rootKey
        self.sendingChainKey = sendingChainKey
        self.receivingChainKey = receivingChainKey
        self.bobFirstMessage = bobFirstMessage
    }

    /// Alice ratchet session initialization after X3DH (Sender State)
    ///
    /// Inputs:
    /// - sharedSecret: 32-byte output from X3DH
    /// - bobRatchetPublic: Bob's signed prekey public key (DH ratchet key published by Bob)
    ///
    /// Initialize:
    /// - DHs = fresh X25519 keypair
    /// - DHr = bobRatchetPublic
    /// - RK, CKs = KDF_RK(sharedSecret, DH(DHs_private, DHr))
    /// - CKr = nil
    /// - Ns = 0, Nr = 0, PNs = 0, MKSKIPPED = empty
    /// - BOB_FIRST_MESSAGE = false
    public static func initSenderState(
        sharedSecret: SymmetricKey,
        bobRatchetPublic: Curve25519.KeyAgreement.PublicKey
    ) throws -> DoubleRatchetSession {
        let dhsPriv = Curve25519.KeyAgreement.PrivateKey()
        let dhsPub = dhsPriv.publicKey

        let dhOut = try dhsPriv.sharedSecretFromKeyAgreement(with: bobRatchetPublic)
        let (newRk, cks) = kdfRk(rk: sharedSecret, dhOut: dhOut)

        return DoubleRatchetSession(
            dhsPrivate: dhsPriv,
            dhsPublic: dhsPub,
            dhrPublic: bobRatchetPublic,
            rootKey: newRk,
            sendingChainKey: cks,
            receivingChainKey: nil,
            bobFirstMessage: false
        )
    }

    /// Alice ratchet session initialization after X3DH (alias for initSenderState)
    public static func initAlice(
        sharedSecret: SymmetricKey,
        bobSpkPublic: Curve25519.KeyAgreement.PublicKey
    ) throws -> DoubleRatchetSession {
        return try initSenderState(sharedSecret: sharedSecret, bobRatchetPublic: bobSpkPublic)
    }

    /// Bob ratchet session initialization after X3DH (Receiver State)
    ///
    /// Inputs:
    /// - sharedSecret: same 32 bytes from X3DH
    /// - bobRatchetKeypair: Bob's signed prekey private key
    ///
    /// Initialize:
    /// - DHs = bobRatchetKeypair
    /// - DHr = nil
    /// - RK = sharedSecret
    /// - CKs = nil, CKr = nil
    /// - Ns = 0, Nr = 0, PNs = 0, MKSKIPPED = empty
    /// - BOB_FIRST_MESSAGE = true
    public static func initReceiverState(
        sharedSecret: SymmetricKey,
        bobRatchetKeypair: Curve25519.KeyAgreement.PrivateKey
    ) -> DoubleRatchetSession {
        return DoubleRatchetSession(
            dhsPrivate: bobRatchetKeypair,
            dhsPublic: bobRatchetKeypair.publicKey,
            dhrPublic: nil,
            rootKey: sharedSecret,
            sendingChainKey: nil,
            receivingChainKey: nil,
            bobFirstMessage: true
        )
    }

    /// Bob ratchet session initialization after X3DH (alias for initReceiverState)
    public static func initBob(
        sharedSecret: SymmetricKey,
        bobSpkKeypair: Curve25519.KeyAgreement.PrivateKey
    ) -> DoubleRatchetSession {
        return initReceiverState(sharedSecret: sharedSecret, bobRatchetKeypair: bobSpkKeypair)
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

    public static let maxSkip: UInt32 = 100
    public static let maxSkippedKeys: Int = 1000

    /// Ratchet Decrypt: Decrypts an inbound message envelope (Sub-Step 4.3).
    ///
    /// 1. Checks skipped keys first: key = header.dh + ":" + header.n
    /// 2. If new peer DH public key (`header.dh != state.DHr`), performs DH ratchet step:
    ///    a. Save skipped keys from current receiving chain up to header.pn
    ///    b. Perform DH ratchet step (Sub-Step 4.4)
    /// 3. Skip messages in the new chain up to header.n
    /// 4. Advance receiving chain: (CKr_new, MK) = KDF_CK(CKr)
    /// 5. Decrypt ciphertext with AES-256-GCM using MK and header as AAD
    public func ratchetDecrypt(envelope: EncryptedEnvelope) throws -> Data {
        guard let peerDhData = Data(base64Encoded: envelope.header.dhPub),
              let peerDhPublic = try? Curve25519.KeyAgreement.PublicKey(rawRepresentation: peerDhData) else {
            throw NSError(domain: "AnonChat", code: 2, userInfo: [NSLocalizedDescriptionKey: "Invalid peer DH public key"])
        }

        // 1. Check skipped keys first
        let skipKey = "\(envelope.header.dhPub):\(envelope.header.n)"
        if let mk = skippedKeys.removeValue(forKey: skipKey) {
            return try decryptWithMK(mk: mk, envelope: envelope)
        }

        // 2. Check for DH ratchet step:
        // In the decrypt function, compare header.dh with state.DHr
        // if header.dh != state.DHr { perform DH ratchet step }
        let isNewDh = (dhrPublic == nil || dhrPublic?.rawRepresentation != peerDhPublic.rawRepresentation)
        if isNewDh {
            // a. Save skipped keys from current receiving chain up to header.pn
            try skipMessageKeys(until: envelope.header.pn)
            // b. Perform DH ratchet step
            try dhRatchet(peerDhPublic: peerDhPublic)
            self.bobFirstMessage = false
        }

        // 3. Skip messages in the new chain up to header.n
        try skipMessageKeys(until: envelope.header.n)

        // 4. Derive message key: (CKr_new, MK) = KDF_CK(CKr)
        guard let currentCkr = receivingChainKey else {
            throw NSError(domain: "AnonChat", code: 3, userInfo: [NSLocalizedDescriptionKey: "Missing receiving chain key"])
        }
        let (nextCkr, mk) = kdfCk(ck: currentCkr)
        self.receivingChainKey = nextCkr
        self.nr += 1
        self.bobFirstMessage = false

        // 5. Decrypt with MK
        return try decryptWithMK(mk: mk, envelope: envelope)
    }

    private func dhRatchet(peerDhPublic: Curve25519.KeyAgreement.PublicKey) throws {
        self.pn = self.ns
        self.ns = 0
        self.nr = 0
        self.dhrPublic = peerDhPublic

        // DH step 1: Derives receiving chain key
        let dhOutRx = try dhsPrivate.sharedSecretFromKeyAgreement(with: peerDhPublic)
        let (newRkRx, ckr) = DoubleRatchetSession.kdfRk(rk: rootKey, dhOut: dhOutRx)
        self.rootKey = newRkRx
        self.receivingChainKey = ckr

        // DH step 2: Generate fresh ephemeral DH keypair and derive sending chain key
        let newDhsPriv = Curve25519.KeyAgreement.PrivateKey()
        let newDhsPub = newDhsPriv.publicKey
        let dhOutTx = try newDhsPriv.sharedSecretFromKeyAgreement(with: peerDhPublic)
        let (newRkTx, cks) = DoubleRatchetSession.kdfRk(rk: newRkRx, dhOut: dhOutTx)
        self.dhsPrivate = newDhsPriv
        self.dhsPublic = newDhsPub
        self.rootKey = newRkTx
        self.sendingChainKey = cks
    }

    private func skipMessageKeys(until: UInt32) throws {
        if until > self.nr + DoubleRatchetSession.maxSkip {
            throw NSError(domain: "AnonChat", code: 4, userInfo: [NSLocalizedDescriptionKey: "Skip gap too large: \(until - self.nr) > \(DoubleRatchetSession.maxSkip)"])
        }
        if let currentCkr = receivingChainKey, let currentDhr = dhrPublic {
            let dhrStr = currentDhr.rawRepresentation.base64EncodedString()
            var ckr = currentCkr
            while self.nr < until {
                if skippedKeys.count >= DoubleRatchetSession.maxSkippedKeys {
                    throw NSError(domain: "AnonChat", code: 5, userInfo: [NSLocalizedDescriptionKey: "Too many skipped message keys"])
                }
                let (nextCkr, mk) = kdfCk(ck: ckr)
                ckr = nextCkr
                skippedKeys["\(dhrStr):\(self.nr)"] = mk
                self.nr += 1
            }
            self.receivingChainKey = ckr
        }
    }

    private func decryptWithMK(mk: SymmetricKey, envelope: EncryptedEnvelope) throws -> Data {
        guard let nonceData = Data(base64Encoded: envelope.nonce),
              let combinedData = Data(base64Encoded: envelope.ciphertext),
              combinedData.count >= 16 else {
            throw NSError(domain: "AnonChat", code: 6, userInfo: [NSLocalizedDescriptionKey: "Invalid ciphertext or nonce"])
        }
        let nonce = try AES.GCM.Nonce(data: nonceData)
        let ct = combinedData.prefix(combinedData.count - 16)
        let tag = combinedData.suffix(16)
        let box = try AES.GCM.SealedBox(nonce: nonce, ciphertext: ct, tag: tag)
        let aad = envelope.header.toAADData()
        let decrypted = try AES.GCM.open(box, using: mk, authenticating: aad)
        return try unpadFrom4KB(data: decrypted)
    }

    private func unpadFrom4KB(data: Data) throws -> Data {
        guard data.count >= 4 else {
            throw NSError(domain: "AnonChat", code: 7, userInfo: [NSLocalizedDescriptionKey: "Padded payload too short"])
        }
        let lenBigEndian = data.prefix(4).withUnsafeBytes { $0.load(as: UInt32.self) }
        let origLen = Int(UInt32(bigEndian: lenBigEndian))
        guard data.count >= 4 + origLen else {
            throw NSError(domain: "AnonChat", code: 8, userInfo: [NSLocalizedDescriptionKey: "Padded payload corrupted: invalid length field"])
        }
        return data.subdata(in: 4..<(4 + origLen))
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

    /// Serializes active ratchet state to JSON for encrypted durable persistence.
    public func toJsonString() -> String {
        var dict: [String: Any] = [:]
        dict["DHs_pub"] = dhsPublic.rawRepresentation.base64EncodedString()
        dict["DHs_priv"] = dhsPrivate.rawRepresentation.base64EncodedString()
        if let dhr = dhrPublic {
            dict["DHr"] = dhr.rawRepresentation.base64EncodedString()
        }
        dict["RK"] = rootKey.withUnsafeBytes { Data($0).base64EncodedString() }
        if let cks = sendingChainKey {
            dict["CKs"] = cks.withUnsafeBytes { Data($0).base64EncodedString() }
        }
        if let ckr = receivingChainKey {
            dict["CKr"] = ckr.withUnsafeBytes { Data($0).base64EncodedString() }
        }
        dict["Ns"] = ns
        dict["Nr"] = nr
        dict["PNs"] = pn
        dict["bob_first_message"] = bobFirstMessage
        var skippedDict: [String: String] = [:]
        for (k, v) in skippedKeys {
            skippedDict[k] = v.withUnsafeBytes { Data($0).base64EncodedString() }
        }
        dict["MKSKIPPED"] = skippedDict
        guard let data = try? JSONSerialization.data(withJSONObject: dict),
              let str = String(data: data, encoding: .utf8) else {
            return "{}"
        }
        return str
    }

    /// Sub-Step SM.3: Persist ratchet state durably before releasing ciphertext to network.
    ///
    /// Research on libsignal store implementations explicitly warns:
    /// "The Double Ratchet has no per-message random nonce guard, so a write that is lost (crash, unflushed buffer)
    /// or rolled back (restored backup, cloned image) makes the next send reuse a message key and IV it has
    /// already used — which costs confidentiality, forward secrecy and replay protection" [citation:25].
    public func durableRatchetEncrypt(
        plaintext: Data,
        saveDurable: (String) throws -> Void,
        sendOverNetwork: (EncryptedEnvelope) throws -> Void
    ) throws -> EncryptedEnvelope {
        let envelope = try ratchetEncrypt(plaintext: plaintext)
        let serialized = toJsonString()
        try saveDurable(serialized)
        try sendOverNetwork(envelope)
        return envelope
    }

    /// Sub-Step SM.3: Persist ratchet state durably before acting on / delivering decrypted plaintext.
    public func durableRatchetDecrypt(
        envelope: EncryptedEnvelope,
        saveDurable: (String) throws -> Void,
        deliverOrDisplay: (Data) throws -> Void
    ) throws -> Data {
        let plaintext = try ratchetDecrypt(envelope: envelope)
        let serialized = toJsonString()
        try saveDurable(serialized)
        try deliverOrDisplay(plaintext)
        return plaintext
    }
}

