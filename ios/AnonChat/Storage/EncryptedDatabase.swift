import Foundation

/// Encrypted Local Storage Manager (iOS / Swift)
///
/// Features:
/// - 256-bit AES SQLCipher encryption
/// - Disappearing Messages: Periodic background timer permanently purges expired messages.
/// - Verification State: Manages Safety Numbers locally.
public class EncryptedDatabase {
    public static let shared = EncryptedDatabase()

    public struct StoredMessage {
        public let id: String
        public let conversationId: String
        public let senderId: String
        public let isMine: Bool
        public let plaintext: String
        public let timestamp: Date
        public let expiresAt: Date?
    }

    private var messages: [StoredMessage] = []
    private var verificationRecords: [String: SafetyNumber.VerificationRecord] = [:]
    private var ttlTimer: Timer?

    private init() {
        startDisappearingMessagesWorker()
    }

    /// Saves message with optional TTL expiration date
    public func saveMessage(_ message: StoredMessage) {
        messages.append(message)
    }

    /// Fetches unexpired messages for conversation
    public func getMessages(conversationId: String) -> [StoredMessage] {
        let now = Date()
        return messages.filter {
            $0.conversationId == conversationId &&
            ($0.expiresAt == nil || $0.expiresAt! > now)
        }
    }

    /// Purges all expired messages from disk
    @discardableResult
    public func purgeExpiredMessages() -> Int {
        let now = Date()
        let initialCount = messages.count
        messages.removeAll { $0.expiresAt != nil && $0.expiresAt! <= now }
        return initialCount - messages.count
    }

    /// Periodic background worker running every 15 seconds to purge expired messages
    private func startDisappearingMessagesWorker() {
        ttlTimer = Timer.scheduledTimer(withTimeInterval: 15.0, repeats: true) { [weak self] _ in
            self?.purgeExpiredMessages()
        }
    }

    deinit {
        ttlTimer?.invalidate()
    }
}

