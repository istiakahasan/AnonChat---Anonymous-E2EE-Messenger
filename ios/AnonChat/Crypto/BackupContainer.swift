import Foundation
import CryptoKit

/// AnonChat Self-Describing Backup Container Format (iOS / Swift)
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
public struct BackupContainer {
    public static let magicBytes: [UInt8] = [0x41, 0x4E, 0x4F, 0x4E] // "ANON"
    public static let version1: UInt8 = 0x01
    public static let kdfIdArgon2id: UInt8 = 0x01
    public static let cipherIdAes256Gcm: UInt8 = 0x01
    public static let headerSize: Int = 42
    public static let saltSize: Int = 16
    public static let nonceSize: Int = 12
    public static let tagSize: Int = 16

    public struct Header: Equatable {
        public let magic: [UInt8]
        public let version: UInt8
        public let kdfId: UInt8
        public let timeCost: UInt8
        public let memoryExponent: UInt8
        public let parallelism: UInt8
        public let salt: Data
        public let cipherId: UInt8
        public let nonce: Data
        public let ciphertextLen: UInt32

        public var memoryKib: UInt64 {
            guard memoryExponent < 64 else { return 0 }
            return 1 << memoryExponent
        }

        public func toData() -> Data {
            var data = Data(capacity: BackupContainer.headerSize)
            data.append(contentsOf: magic)
            data.append(version)
            data.append(kdfId)
            data.append(timeCost)
            data.append(memoryExponent)
            data.append(parallelism)
            data.append(salt)
            data.append(cipherId)
            data.append(nonce)

            var lenLE = ciphertextLen.littleEndian
            withUnsafeBytes(of: &lenLE) { data.append(contentsOf: $0) }
            return data
        }

        public static func fromData(_ data: Data) throws -> Header {
            guard data.count >= BackupContainer.headerSize else {
                throw BackupError.headerTruncated
            }

            let magic = Array(data[0..<4])
            guard magic == BackupContainer.magicBytes else {
                throw BackupError.invalidMagic
            }

            let version = data[4]
            guard version == BackupContainer.version1 else {
                throw BackupError.unsupportedVersion(version)
            }

            let kdfId = data[5]
            guard kdfId == BackupContainer.kdfIdArgon2id else {
                throw BackupError.unsupportedKdf(kdfId)
            }

            let timeCost = data[6]
            let memoryExponent = data[7]
            let parallelism = data[8]
            let salt = data.subdata(in: 9..<25)

            let cipherId = data[25]
            guard cipherId == BackupContainer.cipherIdAes256Gcm else {
                throw BackupError.unsupportedCipher(cipherId)
            }

            let nonce = data.subdata(in: 26..<38)
            let lenLE = data.subdata(in: 38..<42).withUnsafeBytes { $0.load(as: UInt32.self) }
            let ciphertextLen = UInt32(littleEndian: lenLE)

            return Header(
                magic: magic,
                version: version,
                kdfId: kdfId,
                timeCost: timeCost,
                memoryExponent: memoryExponent,
                parallelism: parallelism,
                salt: salt,
                cipherId: cipherId,
                nonce: nonce,
                ciphertextLen: ciphertextLen
            )
        }
    }

    public enum BackupError: Error, Equatable {
        case headerTruncated
        case invalidMagic
        case unsupportedVersion(UInt8)
        case unsupportedKdf(UInt8)
        case unsupportedCipher(UInt8)
        case payloadTruncated
        case decryptionFailed
    }

    public let header: Header
    public let ciphertext: Data

    public func toData() -> Data {
        var data = header.toData()
        data.append(ciphertext)
        return data
    }

    public static func fromData(_ data: Data) throws -> BackupContainer {
        guard data.count >= headerSize else {
            throw BackupError.headerTruncated
        }

        let header = try Header.fromData(data)
        let expectedTotal = headerSize + Int(header.ciphertextLen)
        guard data.count >= expectedTotal else {
            throw BackupError.payloadTruncated
        }

        let ciphertext = data.subdata(in: headerSize..<expectedTotal)
        return BackupContainer(header: header, ciphertext: ciphertext)
    }

    /// Encrypts plaintext with AES-256-GCM using the 42-byte header as AAD.
    public static func encrypt(
        keyData: Data,
        plaintext: Data,
        timeCost: UInt8 = 3,
        memoryExponent: UInt8 = 16,
        parallelism: UInt8 = 4
    ) throws -> BackupContainer {
        var salt = Data(count: saltSize)
        var nonceData = Data(count: nonceSize)
        _ = salt.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, saltSize, $0.baseAddress!) }
        _ = nonceData.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, nonceSize, $0.baseAddress!) }

        let ciphertextLen = UInt32(plaintext.count + tagSize)
        let header = Header(
            magic: magicBytes,
            version: version1,
            kdfId: kdfIdArgon2id,
            timeCost: timeCost,
            memoryExponent: memoryExponent,
            parallelism: parallelism,
            salt: salt,
            cipherId: cipherIdAes256Gcm,
            nonce: nonceData,
            ciphertextLen: ciphertextLen
        )

        let headerData = header.toData()
        let symmetricKey = SymmetricKey(data: keyData)
        let nonce = try AES.GCM.Nonce(data: nonceData)

        let sealed = try AES.GCM.seal(plaintext, using: symmetricKey, nonce: nonce, authenticating: headerData)
        let ciphertext = sealed.ciphertext + sealed.tag

        return BackupContainer(header: header, ciphertext: ciphertext)
    }

    /// Decrypts container and authenticates the 42-byte header AAD.
    public func decrypt(keyData: Data) throws -> Data {
        guard ciphertext.count >= BackupContainer.tagSize else {
            throw BackupError.decryptionFailed
        }

        let headerData = header.toData()
        let symmetricKey = SymmetricKey(data: keyData)
        let nonce = try AES.GCM.Nonce(data: header.nonce)

        let ctOnly = ciphertext.subdata(in: 0..<(ciphertext.count - BackupContainer.tagSize))
        let tag = ciphertext.subdata(in: (ciphertext.count - BackupContainer.tagSize)..<ciphertext.count)

        let sealedBox = try AES.GCM.SealedBox(nonce: nonce, ciphertext: ctOnly, tag: tag)
        let plaintext = try AES.GCM.open(sealedBox, using: symmetricKey, authenticating: headerData)

        return plaintext
    }
}
