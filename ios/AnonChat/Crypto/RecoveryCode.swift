import Foundation
import CryptoKit

/// High-Entropy Recovery Code Implementation (iOS / Swift)
///
/// Implements:
/// - Option B (Recommended): 24-word BIP39 mnemonic phrase (256-bit entropy + 8-bit SHA-256 checksum)
/// - Option A: Crockford Base32 52-character recovery code in 13 groups of 4 separated by spaces
public struct RecoveryCode {
    public static let crockfordAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

    public enum RecoveryCodeError: Error, LocalizedError {
        case invalidEntropyLength(Int)
        case invalidWordCount(Int)
        case wordNotFound(String, Int)
        case invalidChecksum
        case invalidBase32Length(Int)
        case invalidBase32Character(Character)
        case unrecognizedFormat

        public var errorDescription: String? {
            switch self {
            case .invalidEntropyLength(let len):
                return "Invalid entropy length: expected 32 bytes, got \(len)"
            case .invalidWordCount(let count):
                return "Invalid word count: expected 24 words, got \(count)"
            case .wordNotFound(let word, let pos):
                return "Word not found in BIP39 wordlist: '\(word)' at position \(pos)"
            case .invalidChecksum:
                return "Invalid BIP39 checksum: phrase may be mistyped or corrupted"
            case .invalidBase32Length(let len):
                return "Invalid Base32 length: expected 52 characters, got \(len)"
            case .invalidBase32Character(let char):
                return "Invalid Base32 character: '\(char)'"
            case .unrecognizedFormat:
                return "Unrecognized recovery code format: must be 24 BIP39 words or 52 Base32 characters"
            }
        }
    }

    /// Generates 256 bits (32 bytes) of cryptographically secure random entropy.
    public static func generateEntropy256() -> Data {
        var bytes = [UInt8](repeating: 0, count: 32)
        _ = SecRandomCopyBytes(kSecRandomDefault, 32, &bytes)
        return Data(bytes)
    }

    /// Encodes 32-byte (256-bit) entropy into a 24-word BIP39 mnemonic phrase.
    public static func entropyToBip39(entropy: Data) throws -> String {
        guard entropy.count == 32 else {
            throw RecoveryCodeError.invalidEntropyLength(entropy.count)
        }

        // 1. Calculate 8-bit checksum: first byte of SHA-256(entropy)
        let hash = SHA256.hash(data: entropy)
        guard let checksumByte = hash.first else {
            throw RecoveryCodeError.invalidChecksum
        }

        // 2. Build 264-bit stream
        var bits = [Bool]()
        bits.reserveCapacity(264)
        for byte in entropy {
            for bitIdx in (0...7).reversed() {
                bits.append(((byte >> bitIdx) & 1) == 1)
            }
        }
        for bitIdx in (0...7).reversed() {
            bits.append(((checksumByte >> bitIdx) & 1) == 1)
        }

        // 3. Extract 24 chunks of 11 bits each
        var words = [String]()
        for i in 0..<24 {
            var wordIdx = 0
            for bitOffset in 0..<11 {
                let bitVal = bits[i * 11 + bitOffset] ? 1 : 0
                wordIdx = (wordIdx << 1) | bitVal
            }
            words.append(Bip39Words.words[wordIdx])
        }

        return words.joined(separator: " ")
    }

    /// Decodes and validates a 24-word BIP39 mnemonic phrase, recovering 32-byte entropy.
    public static func bip39ToEntropy(phrase: String) throws -> Data {
        let words = phrase
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .lowercased()
            .components(separatedBy: .whitespacesAndNewlines)
            .filter { !$0.isEmpty }

        guard words.count == 24 else {
            throw RecoveryCodeError.invalidWordCount(words.count)
        }

        var bits = [Bool]()
        bits.reserveCapacity(264)
        for (i, word) in words.enumerated() {
            guard let wordIdx = Bip39Words.words.firstIndex(of: word) else {
                throw RecoveryCodeError.wordNotFound(word, i + 1)
            }
            for bitIdx in (0...10).reversed() {
                bits.append(((wordIdx >> bitIdx) & 1) == 1)
            }
        }

        // Extract 32-byte entropy
        var entropyBytes = [UInt8](repeating: 0, count: 32)
        for byteIdx in 0..<32 {
            var byteVal: UInt8 = 0
            for bitOffset in 0..<8 {
                let bitVal: UInt8 = bits[byteIdx * 8 + bitOffset] ? 1 : 0
                byteVal = (byteVal << 1) | bitVal
            }
            entropyBytes[byteIdx] = byteVal
        }
        let entropyData = Data(entropyBytes)

        // Extract 8-bit checksum
        var expectedChecksum: UInt8 = 0
        for bitOffset in 0..<8 {
            let bitVal: UInt8 = bits[256 + bitOffset] ? 1 : 0
            expectedChecksum = (expectedChecksum << 1) | bitVal
        }

        // Verify checksum
        let hash = SHA256.hash(data: entropyData)
        guard let actualChecksum = hash.first, actualChecksum == expectedChecksum else {
            throw RecoveryCodeError.invalidChecksum
        }

        return entropyData
    }

    /// Generates a fresh 24-word BIP39 recovery code (Option B - Recommended).
    public static func generateBip39RecoveryCode() throws -> String {
        return try entropyToBip39(entropy: generateEntropy256())
    }

    /// Encodes 32-byte (256-bit) entropy into Crockford Base32 (Option A: 52 characters in groups of 4).
    public static func entropyToBase32(entropy: Data) throws -> String {
        guard entropy.count == 32 else {
            throw RecoveryCodeError.invalidEntropyLength(entropy.count)
        }

        var bits = [Bool]()
        bits.reserveCapacity(260)
        for byte in entropy {
            for bitIdx in (0...7).reversed() {
                bits.append(((byte >> bitIdx) & 1) == 1)
            }
        }
        // 4 trailing zero padding bits
        bits.append(contentsOf: [false, false, false, false])

        let alphabetArray = Array(crockfordAlphabet)
        var chars = [Character]()
        for i in 0..<52 {
            var valIdx = 0
            for bitOffset in 0..<5 {
                let bitVal = bits[i * 5 + bitOffset] ? 1 : 0
                valIdx = (valIdx << 1) | bitVal
            }
            chars.append(alphabetArray[valIdx])
        }

        var groups = [String]()
        for i in stride(from: 0, to: 52, by: 4) {
            groups.append(String(chars[i..<i + 4]))
        }
        return groups.joined(separator: " ")
    }

    /// Decodes Crockford Base32 recovery code into 32-byte entropy.
    public static func base32ToEntropy(code: String) throws -> Data {
        var normalized = code
            .replacingOccurrences(of: "[\\s-]+", with: "", options: .regularExpression)
            .uppercased()

        normalized = normalized
            .replacingOccurrences(of: "O", with: "0")
            .replacingOccurrences(of: "I", with: "1")
            .replacingOccurrences(of: "L", with: "1")

        guard normalized.count == 52 else {
            throw RecoveryCodeError.invalidBase32Length(normalized.count)
        }

        let alphabetArray = Array(crockfordAlphabet)
        var bits = [Bool]()
        bits.reserveCapacity(260)
        for c in normalized {
            guard let idx = alphabetArray.firstIndex(of: c) else {
                throw RecoveryCodeError.invalidBase32Character(c)
            }
            for bitIdx in (0...4).reversed() {
                bits.append(((idx >> bitIdx) & 1) == 1)
            }
        }

        var entropyBytes = [UInt8](repeating: 0, count: 32)
        for byteIdx in 0..<32 {
            var byteVal: UInt8 = 0
            for bitOffset in 0..<8 {
                let bitVal: UInt8 = bits[byteIdx * 8 + bitOffset] ? 1 : 0
                byteVal = (byteVal << 1) | bitVal
            }
            entropyBytes[byteIdx] = byteVal
        }

        return Data(entropyBytes)
    }

    /// Generates a fresh Crockford Base32 recovery code (Option A: 52 characters in 13 groups of 4).
    public static func generateBase32RecoveryCode() throws -> String {
        return try entropyToBase32(entropy: generateEntropy256())
    }

    /// Validates any recovery code (BIP39 24 words or Base32 52 characters).
    public static func validateRecoveryCode(input: String) throws -> Data {
        let trimmed = input.trimmingCharacters(in: .whitespacesAndNewlines)
        let words = trimmed.components(separatedBy: .whitespacesAndNewlines).filter { !$0.isEmpty }

        if words.count == 24 {
            return try bip39ToEntropy(phrase: trimmed)
        }

        let stripped = trimmed.replacingOccurrences(of: "[\\s-]+", with: "", options: .regularExpression)
        if stripped.count == 52 {
            return try base32ToEntropy(code: trimmed)
        }

        throw RecoveryCodeError.unrecognizedFormat
    }
}
