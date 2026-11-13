//! AnonChat Signal Protocol Safety Number Derivation
//!
//! Specification:
//! 1. Individual Fingerprint:
//!    - Initial digest: SHA-512(identityKeyPublicBytes || identifier)
//!    - Key Stretching: 5,200 iterations of SHA-512(previous_hash || identityKeyPublicBytes)
//!    - Extract 6 groups of 5 digits (30 digits per user) via 4-byte big-endian chunks % 100,000.
//! 2. Lexicographical Ordering:
//!    - Sort the two 30-digit fingerprints so Alice and Bob compute the identical sequence.
//! 3. Concatenate and format:
//!    - 60 digits total, formatted as 12 groups of 5 digits separated by spaces.
//!
//! Verification State Storage (Local Only):
//! - Contact verification state (safetyNumber, verifiedAt, lastRemoteKey) is stored strictly
//!   in local encrypted storage (SQLCipher).
//! - NEVER uploaded or exposed to the relay server.

use sha2::{Digest, Sha512};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

pub const SIGNAL_FINGERPRINT_ITERATIONS: usize = 5200;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContactVerificationState {
    pub contact_id: String,
    pub safety_number: String,
    pub verified_at: Option<u64>,
    pub last_remote_key_hex: String,
}

impl ContactVerificationState {
    pub fn new(contact_id: &str, safety_number: &str, remote_key_hex: &str) -> Self {
        Self {
            contact_id: contact_id.to_string(),
            safety_number: safety_number.to_string(),
            verified_at: None,
            last_remote_key_hex: remote_key_hex.to_string(),
        }
    }

    /// Marks the contact's safety number as manually verified by the user.
    pub fn mark_verified(&mut self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.verified_at = Some(now);
    }

    /// Checks if a newly observed remote identity key matches the trusted key.
    /// If changed, un-verifies the contact and requires re-confirmation.
    pub fn check_key_update(&mut self, new_remote_key_hex: &str, new_safety_number: &str) -> bool {
        if self.last_remote_key_hex != new_remote_key_hex {
            self.last_remote_key_hex = new_remote_key_hex.to_string();
            self.safety_number = new_safety_number.to_string();
            self.verified_at = None; // Reset trust!
            return false; // Key changed!
        }
        true // Key matches
    }

    /// Explicitly accepts a new identity key without verification (user accepts risk).
    pub fn accept_new_key_without_verification(&mut self, new_remote_key_hex: &str, new_safety_number: &str) {
        self.last_remote_key_hex = new_remote_key_hex.to_string();
        self.safety_number = new_safety_number.to_string();
        self.verified_at = None;
    }
}

/// Derives a 30-digit fingerprint for an individual identity key and user identifier.
/// Uses 5,200 iterations of SHA-512 to prevent key grinding.
pub fn compute_individual_fingerprint(identity_key: &[u8], identifier: &str) -> String {
    // Initial round: SHA-512(identityKey || identifier)
    let mut hasher = Sha512::new();
    hasher.update(identity_key);
    hasher.update(identifier.as_bytes());
    let mut digest = hasher.finalize();

    // 5,200 iterations of SHA-512(digest || identityKey)
    for _ in 0..SIGNAL_FINGERPRINT_ITERATIONS {
        let mut h = Sha512::new();
        h.update(&digest);
        h.update(identity_key);
        digest = h.finalize();
    }

    // Extract 6 groups of 5 digits (30 digits total) from the 64-byte digest
    let mut fingerprint_digits = String::with_capacity(30);
    for i in 0..6 {
        let start = i * 4;
        let chunk = u32::from_be_bytes([
            digest[start],
            digest[start + 1],
            digest[start + 2],
            digest[start + 3],
        ]);
        let five_digits = chunk % 100_000;
        fingerprint_digits.push_str(&format!("{:05}", five_digits));
    }

    fingerprint_digits
}

/// Derives the full, deterministic 60-digit Safety Number for two communicating parties.
///
/// Determinism Guarantee:
/// `derive_safety_number(A_key, A_id, B_key, B_id) == derive_safety_number(B_key, B_id, A_key, A_id)`
///
/// Output Format:
/// "12345 67890 12345 67890 12345 67890 12345 67890 12345 67890 12345 67890"
pub fn derive_safety_number(
    user_a_key: &[u8],
    user_a_id: &str,
    user_b_key: &[u8],
    user_b_id: &str,
) -> String {
    let fp_a = compute_individual_fingerprint(user_a_key, user_a_id);
    let fp_b = compute_individual_fingerprint(user_b_key, user_b_id);

    // Lexicographical sort ensures Alice and Bob obtain identical results regardless of initiator
    let (first, second) = if fp_a <= fp_b {
        (fp_a, fp_b)
    } else {
        (fp_b, fp_a)
    };

    let combined = format!("{}{}", first, second);
    debug_assert_eq!(combined.len(), 60);

    // Format as 12 groups of 5 digits separated by spaces
    let mut formatted_groups = Vec::with_capacity(12);
    for i in 0..12 {
        let start = i * 5;
        let end = start + 5;
        formatted_groups.push(&combined[start..end]);
    }

    formatted_groups.join(" ")
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_safety_number_symmetric_and_formatted() {
        let a = [0x11u8; 32];
        let b = [0x22u8; 32];
        let ab = derive_safety_number(&a, "alice", &b, "bob");
        let ba = derive_safety_number(&b, "bob", &a, "alice");
        assert_eq!(ab, ba, "Alice and Bob must compute the identical safety number");
        let groups: Vec<&str> = ab.split(' ').collect();
        assert_eq!(groups.len(), 12);
        assert!(groups.iter().all(|g| g.len() == 5 && g.chars().all(|c| c.is_ascii_digit())));
    }

    #[test]
    fn test_key_change_resets_verification() {
        let mut state = ContactVerificationState::new("bob", "11111 22222", "aa");
        state.mark_verified();
        assert!(state.verified_at.is_some());

        // Same key: still trusted
        assert!(state.check_key_update("aa", "11111 22222"));
        assert!(state.verified_at.is_some());

        // Changed key: reported, trust reset, new key/number recorded
        assert!(!state.check_key_update("bb", "33333 44444"));
        assert!(state.verified_at.is_none());
        assert_eq!(state.last_remote_key_hex, "bb");
        assert_eq!(state.safety_number, "33333 44444");
    }

    #[test]
    fn test_accept_new_key_without_verification_stays_unverified() {
        let mut state = ContactVerificationState::new("bob", "11111 22222", "aa");
        state.mark_verified();
        state.accept_new_key_without_verification("cc", "55555 66666");
        assert!(state.verified_at.is_none(), "accepting unverified must never mark verified");
        assert_eq!(state.last_remote_key_hex, "cc");
        assert_eq!(state.safety_number, "55555 66666");
        // The accepted key is now the trusted baseline, so no repeated change alert
        assert!(state.check_key_update("cc", "55555 66666"));
    }
}
