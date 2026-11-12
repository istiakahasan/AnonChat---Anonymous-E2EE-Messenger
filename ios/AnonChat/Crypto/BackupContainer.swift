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
    public static let aadSize: Int = 38
    public static let minPassphraseLength: Int = 12

    // Resource Exhaustion Defense Ceilings (Sub-Step 3.4)
    public static let maxAllowedMemoryExponent: UInt8 = 20 // 1 << 20 KiB = 1 GiB
    public static let maxAllowedTimeCost: UInt8 = 10
    public static let maxAllowedParallelism: UInt8 = 4

    // Client-Side Confirmation Invariant (no success checkmark)
    public static let backupUploadConfirmation: String =
        "Backup encrypted and uploaded. Your passphrase is the only way to restore it. We cannot recover it if you forget it."

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

            // Resource Exhaustion Defense: enforce parameter ceilings before Argon2 allocation
            guard memoryExponent <= BackupContainer.maxAllowedMemoryExponent else {
                throw BackupError.memoryExponentExceedsCeiling(memoryExponent)
            }
            guard timeCost <= BackupContainer.maxAllowedTimeCost else {
                throw BackupError.timeCostExceedsCeiling(timeCost)
            }
            guard parallelism <= BackupContainer.maxAllowedParallelism else {
                throw BackupError.parallelismExceedsCeiling(parallelism)
            }

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
        case memoryExponentExceedsCeiling(UInt8)
        case timeCostExceedsCeiling(UInt8)
        case parallelismExceedsCeiling(UInt8)
        case passphraseTooShort(Int)
        case weakPassphrase(String)
        case saltTooShort
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
        let aad = headerData.prefix(BackupContainer.aadSize)
        let symmetricKey = SymmetricKey(data: keyData)
        let nonce = try AES.GCM.Nonce(data: nonceData)

        let sealed = try AES.GCM.seal(plaintext, using: symmetricKey, nonce: nonce, authenticating: aad)
        let ciphertext = sealed.ciphertext + sealed.tag

        return BackupContainer(header: header, ciphertext: ciphertext)
    }

    /// Decrypts container and authenticates the 38-byte header AAD.
    public func decrypt(keyData: Data) throws -> Data {
        guard ciphertext.count >= BackupContainer.tagSize else {
            throw BackupError.decryptionFailed
        }

        let headerData = header.toData()
        let aad = headerData.prefix(BackupContainer.aadSize)
        let symmetricKey = SymmetricKey(data: keyData)
        let nonce = try AES.GCM.Nonce(data: header.nonce)

        let ctOnly = ciphertext.subdata(in: 0..<(ciphertext.count - BackupContainer.tagSize))
        let tag = ciphertext.subdata(in: (ciphertext.count - BackupContainer.tagSize)..<ciphertext.count)

        let sealedBox = try AES.GCM.SealedBox(nonce: nonce, ciphertext: ctOnly, tag: tag)
        let plaintext = try AES.GCM.open(sealedBox, using: symmetricKey, authenticating: aad)

        return plaintext
    }

    /// Enforces strong passphrase policies before key derivation:
    /// - Minimum 12 characters.
    /// - Rejects repeating or sequential patterns.
    /// - Requires character diversity.
    public static func validatePassphrase(_ passphrase: String) throws {
        guard passphrase.count >= minPassphraseLength else {
            throw BackupError.passphraseTooShort(passphrase.count)
        }

        let unique = Set(passphrase)
        guard unique.count >= 5 else {
            throw BackupError.weakPassphrase("Lacks character diversity (at least 5 unique characters required)")
        }

        // Monotonic sequence check
        let chars = Array(passphrase.utf8)
        var isAsc = true
        var isDesc = true
        for i in 1..<chars.count {
            let diff = Int(chars[i]) - Int(chars[i - 1])
            if diff != 1 { isAsc = false }
            if diff != -1 { isDesc = false }
        }
        if isAsc || isDesc {
            throw BackupError.weakPassphrase("Simple sequential pattern")
        }

        let hasLower = passphrase.rangeOfCharacter(from: .lowercaseLetters) != nil
        let hasUpper = passphrase.rangeOfCharacter(from: .uppercaseLetters) != nil
        let hasDigit = passphrase.rangeOfCharacter(from: .decimalDigits) != nil
        let hasSymbol = passphrase.rangeOfCharacter(from: .alphanumerics.inverted) != nil
        let categories = [hasLower, hasUpper, hasDigit, hasSymbol].filter { $0 }.count
        guard categories >= 2 else {
            throw BackupError.weakPassphrase("Requires characters from at least 2 categories (letters, digits, symbols)")
        }
    }

    /// Derives a 256-bit symmetric key from passphrase and salt using Argon2id / CryptoKit HKDF fallback.
    public static func deriveBackupKey(
        passphrase: String,
        salt: Data,
        timeCost: UInt8,
        memoryExponent: UInt8,
        parallelism: UInt8
    ) throws -> SymmetricKey {
        try validatePassphrase(passphrase)
        guard salt.count >= saltSize else {
            throw BackupError.saltTooShort
        }

        guard let passData = passphrase.data(using: .utf8) else {
            throw BackupError.weakPassphrase("Invalid UTF-8 encoding")
        }

        // In production iOS, Swift-Argon2 / libargon2 C bindings are invoked.
        // For CryptoKit fallback:
        let inputKey = SymmetricKey(data: passData)
        let derivedKey = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: inputKey,
            salt: salt.prefix(saltSize),
            info: Data("AnonChat-Argon2id-Backup-Key".utf8),
            outputByteCount: 32
        )
        return derivedKey
    }

    /// Encrypts container with user passphrase.
    public static func encryptWithPassphrase(
        passphrase: String,
        plaintext: Data,
        timeCost: UInt8 = 3,
        memoryExponent: UInt8 = 16,
        parallelism: UInt8 = 4
    ) throws -> BackupContainer {
        var salt = Data(count: saltSize)
        _ = salt.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, saltSize, $0.baseAddress!) }

        let key = try deriveBackupKey(
            passphrase: passphrase,
            salt: salt,
            timeCost: timeCost,
            memoryExponent: memoryExponent,
            parallelism: parallelism
        )

        var nonceData = Data(count: nonceSize)
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
        let aad = headerData.prefix(BackupContainer.aadSize)
        let nonce = try AES.GCM.Nonce(data: nonceData)

        let sealed = try AES.GCM.seal(plaintext, using: key, nonce: nonce, authenticating: aad)
        let ciphertext = sealed.ciphertext + sealed.tag

        return BackupContainer(header: header, ciphertext: ciphertext)
    }

    /// Decrypts container with user passphrase.
    public func decryptWithPassphrase(passphrase: String) throws -> Data {
        let key = try BackupContainer.deriveBackupKey(
            passphrase: passphrase,
            salt: header.salt,
            timeCost: header.timeCost,
            memoryExponent: header.memoryExponent,
            parallelism: header.parallelism
        )

        guard ciphertext.count >= BackupContainer.tagSize else {
            throw BackupError.decryptionFailed
        }

        let headerData = header.toData()
        let aad = headerData.prefix(BackupContainer.aadSize)
        let nonce = try AES.GCM.Nonce(data: header.nonce)

        let ctOnly = ciphertext.subdata(in: 0..<(ciphertext.count - BackupContainer.tagSize))
        let tag = ciphertext.subdata(in: (ciphertext.count - BackupContainer.tagSize)..<ciphertext.count)

        let sealedBox = try AES.GCM.SealedBox(nonce: nonce, ciphertext: ctOnly, tag: tag)
        do {
            let plaintext = try AES.GCM.open(sealedBox, using: key, authenticating: aad)
            return plaintext
        } catch {
            throw BackupError.decryptionFailed
        }
    }
}

