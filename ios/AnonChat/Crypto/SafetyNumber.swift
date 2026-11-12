import Foundation
import CryptoKit

/// Signal Protocol 60-Digit Safety Number Derivation (iOS / Swift)
///
/// Algorithm:
/// 1. For each user:
///    - Initial round: SHA-512(identityKeyBytes + identifier)
///    - 5,200 iterations of SHA-512(previous_digest + identityKeyBytes)
///    - Extract 6 groups of 5 digits (30 digits total) using 4-byte big-endian chunks % 100,000.
/// 2. Lexicographically sort the two 30-digit fingerprints.
/// 3. Concatenate the two fingerprints into 60 digits total.
/// 4. Format as 12 groups of 5 digits separated by spaces.
///
/// Verification State Storage (Local Only):
/// - Persisted in Apple Keychain / SQLCipher (never uploaded to relay server).
public class SafetyNumber {
    public static let fingerprintIterations = 5200

    public struct VerificationRecord: Codable {
        public let contactId: String
        public let safetyNumber: String
        public var verifiedAt: Date?
        public var lastRemoteKeyHex: String
    }

    /// Computes the 30-digit individual fingerprint using 5,200 SHA-512 iterations.
    public static func computeIndividualFingerprint(identityKey: Data, identifier: String) -> String {
        let idData = identifier.data(using: .utf8) ?? Data()

        // Initial round: SHA-512(identityKey + identifier)
        var hasher = SHA512()
        hasher.update(data: identityKey)
        hasher.update(data: idData)
        var digest = hasher.finalize()

        // 5,200 iterations: SHA-512(digest + identityKey)
        for _ in 0..<fingerprintIterations {
            var roundHasher = SHA512()
            roundHasher.update(data: Data(digest))
            roundHasher.update(data: identityKey)
            digest = roundHasher.finalize()
        }

        let digestData = Data(digest)
        var fingerprint = ""

        // Extract 6 groups of 5 digits from 4-byte big-endian chunks % 100,000
        for i in 0..<6 {
            let start = i * 4
            let chunkData = digestData.subdata(in: start..<(start + 4))
            let chunk = UInt32(bigEndian: chunkData.withUnsafeBytes { $0.load(as: UInt32.self) })
            let fiveDigits = String(format: "%05d", chunk % 100_000)
            fingerprint += fiveDigits
        }

        return fingerprint
    }

    /// Derives the 60-digit deterministic composite Safety Number for two parties.
    public static func generateCompositeSafetyNumber(
        localIdentityKey: Data,
        localIdentifier: String,
        remoteIdentityKey: Data,
        remoteIdentifier: String
    ) -> String {
        let fpA = computeIndividualFingerprint(identityKey: localIdentityKey, identifier: localIdentifier)
        let fpB = computeIndividualFingerprint(identityKey: remoteIdentityKey, identifier: remoteIdentifier)

        // Lexicographical sort ensures symmetry between both participants
        let sorted = [fpA, fpB].sorted()
        let combined = sorted[0] + sorted[1]

        // Format as 12 groups of 5 digits separated by spaces
        var groups: [String] = []
        for i in 0..<12 {
            let start = combined.index(combined.startIndex, offsetBy: i * 5)
            let end = combined.index(start, offsetBy: 5)
            groups.append(String(combined[start..<end]))
        }

        return groups.joined(separator: " ")
    }
}

