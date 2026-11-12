//! High-Entropy Recovery Code for Backup Containers (BIP39 & Base32)
//!
//! Provides two human-transcribable 256-bit high-entropy formats:
//! - **Option B (Recommended)**: BIP39-style 24-word mnemonic from standard English wordlist
//!   (256 bits entropy + 8-bit SHA-256 checksum = 264 bits = 24 words).
//! - **Option A**: Crockford Base32 52-character code in 13 groups of 4 separated by spaces
//!   (e.g., `K7QM 3XPR 9WTF 2BNH ...`).

use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

pub const BIP39_WORD_COUNT: usize = 24;
pub const BASE32_CHAR_COUNT: usize = 52;
pub const CROCKFORD_ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

const WORDLIST_RAW: &str = include_str!("bip39_english.txt");

#[derive(Error, Debug, PartialEq, Eq)]
pub enum RecoveryCodeError {
    #[error("Invalid word count: expected 24 words, got {0}")]
    InvalidWordCount(usize),
    #[error("Word not found in BIP39 wordlist: '{0}' at position {1}")]
    WordNotFound(String, usize),
    #[error("Invalid BIP39 checksum: phrase may be mistyped or corrupted")]
    InvalidChecksum,
    #[error("Invalid Base32 character length: expected 52 characters, got {0}")]
    InvalidBase32Length(usize),
    #[error("Invalid Base32 character: '{0}'")]
    InvalidBase32Char(char),
    #[error("Unrecognized recovery code format: must be 24 BIP39 words or 52 Base32 characters")]
    UnrecognizedFormat,
}

/// Returns the static slice of 2048 BIP39 English words.
pub fn get_bip39_wordlist() -> Vec<&'static str> {
    WORDLIST_RAW.lines().map(|l| l.trim()).filter(|l| !l.is_empty()).collect()
}

/// Generates a fresh 256-bit random entropy buffer using CSPRNG.
pub fn generate_entropy_256() -> Zeroizing<[u8; 32]> {
    let mut entropy = [0u8; 32];
    OsRng.fill_bytes(&mut entropy);
    Zeroizing::new(entropy)
}

/// Encodes 32-byte (256-bit) entropy into a 24-word BIP39 mnemonic phrase.
pub fn entropy_to_bip39(entropy: &[u8; 32]) -> String {
    let wordlist = get_bip39_wordlist();
    assert_eq!(wordlist.len(), 2048, "BIP39 wordlist must contain exactly 2048 words");

    // 1. Calculate 8-bit checksum: first byte of SHA-256(entropy)
    let checksum = Sha256::digest(entropy)[0];

    // 2. Build 264-bit stream: 256 bits entropy + 8 bits checksum
    let mut bits = Vec::with_capacity(264);
    for &byte in entropy {
        for bit_idx in (0..8).rev() {
            bits.push((byte >> bit_idx) & 1);
        }
    }
    for bit_idx in (0..8).rev() {
        bits.push((checksum >> bit_idx) & 1);
    }

    // 3. Extract 24 chunks of 11 bits each
    let mut words = Vec::with_capacity(BIP39_WORD_COUNT);
    for i in 0..BIP39_WORD_COUNT {
        let mut word_idx = 0usize;
        for bit_offset in 0..11 {
            word_idx = (word_idx << 1) | (bits[i * 11 + bit_offset] as usize);
        }
        words.push(wordlist[word_idx]);
    }

    words.join(" ")
}

/// Decodes and validates a 24-word BIP39 mnemonic phrase, recovering the 32-byte entropy.
pub fn bip39_to_entropy(phrase: &str) -> Result<Zeroizing<[u8; 32]>, RecoveryCodeError> {
    let wordlist = get_bip39_wordlist();
    let words: Vec<&str> = phrase.split_whitespace().collect();

    if words.len() != BIP39_WORD_COUNT {
        return Err(RecoveryCodeError::InvalidWordCount(words.len()));
    }

    // Convert words to 264-bit stream
    let mut bits = Vec::with_capacity(264);
    for (pos, &w) in words.iter().enumerate() {
        let clean_word = w.to_lowercase();
        match wordlist.iter().position(|&x| x == clean_word) {
            Some(idx) => {
                for bit_idx in (0..11).rev() {
                    bits.push(((idx >> bit_idx) & 1) as u8);
                }
            }
            None => {
                return Err(RecoveryCodeError::WordNotFound(clean_word, pos + 1));
            }
        }
    }

    // Extract 32-byte entropy (first 256 bits)
    let mut entropy = [0u8; 32];
    for byte_idx in 0..32 {
        let mut byte = 0u8;
        for bit_offset in 0..8 {
            byte = (byte << 1) | bits[byte_idx * 8 + bit_offset];
        }
        entropy[byte_idx] = byte;
    }

    // Extract 8-bit checksum
    let mut expected_checksum = 0u8;
    for bit_offset in 0..8 {
        expected_checksum = (expected_checksum << 1) | bits[256 + bit_offset];
    }

    // Verify SHA-256 checksum
    let computed_checksum = Sha256::digest(&entropy)[0];
    if computed_checksum != expected_checksum {
        return Err(RecoveryCodeError::InvalidChecksum);
    }

    Ok(Zeroizing::new(entropy))
}

/// Generates a fresh 24-word BIP39 recovery code (Option B - Recommended).
pub fn generate_bip39_recovery_code() -> String {
    let entropy = generate_entropy_256();
    entropy_to_bip39(&entropy)
}

/// Encodes 32-byte (256-bit) entropy into Crockford Base32 (Option A: 52 characters in groups of 4).
pub fn entropy_to_base32(entropy: &[u8; 32]) -> String {
    // 256 bits of entropy + 4 bits zero padding = 260 bits = 52 characters * 5 bits
    let mut bits = Vec::with_capacity(260);
    for &byte in entropy {
        for bit_idx in (0..8).rev() {
            bits.push((byte >> bit_idx) & 1);
        }
    }
    // 4 padding zero bits
    bits.extend_from_slice(&[0, 0, 0, 0]);

    let mut chars = Vec::with_capacity(BASE32_CHAR_COUNT);
    for i in 0..BASE32_CHAR_COUNT {
        let mut val = 0usize;
        for bit_offset in 0..5 {
            val = (val << 1) | (bits[i * 5 + bit_offset] as usize);
        }
        chars.push(CROCKFORD_ALPHABET[val] as char);
    }

    // Format in 13 groups of 4 separated by spaces
    let mut groups = Vec::with_capacity(13);
    for chunk in chars.chunks(4) {
        groups.push(chunk.iter().collect::<String>());
    }
    groups.join(" ")
}

/// Decodes Crockford Base32 recovery code into 32-byte entropy.
pub fn base32_to_entropy(code: &str) -> Result<Zeroizing<[u8; 32]>, RecoveryCodeError> {
    // Normalize string: strip whitespace and hyphens, uppercase, normalize O->0, I/L->1
    let mut normalized = String::with_capacity(code.len());
    for c in code.chars() {
        if c.is_whitespace() || c == '-' {
            continue;
        }
        let upper = c.to_ascii_uppercase();
        let mapped = match upper {
            'O' => '0',
            'I' | 'L' => '1',
            _ => upper,
        };
        normalized.push(mapped);
    }

    if normalized.len() != BASE32_CHAR_COUNT {
        return Err(RecoveryCodeError::InvalidBase32Length(normalized.len()));
    }

    let mut bits = Vec::with_capacity(260);
    for c in normalized.chars() {
        match CROCKFORD_ALPHABET.iter().position(|&x| x as char == c) {
            Some(idx) => {
                for bit_idx in (0..5).rev() {
                    bits.push(((idx >> bit_idx) & 1) as u8);
                }
            }
            None => {
                return Err(RecoveryCodeError::InvalidBase32Char(c));
            }
        }
    }

    let mut entropy = [0u8; 32];
    for byte_idx in 0..32 {
        let mut byte = 0u8;
        for bit_offset in 0..8 {
            byte = (byte << 1) | bits[byte_idx * 8 + bit_offset];
        }
        entropy[byte_idx] = byte;
    }

    Ok(Zeroizing::new(entropy))
}

/// Generates a fresh Crockford Base32 recovery code (Option A: 52 characters in 13 groups of 4).
pub fn generate_base32_recovery_code() -> String {
    let entropy = generate_entropy_256();
    entropy_to_base32(&entropy)
}

/// Unified validator: Automatically detects and validates BIP39 24-word or Base32 recovery codes.
pub fn validate_recovery_code(input: &str) -> Result<Zeroizing<[u8; 32]>, RecoveryCodeError> {
    let trimmed = input.trim();
    let words: Vec<&str> = trimmed.split_whitespace().collect();

    if words.len() == BIP39_WORD_COUNT {
        bip39_to_entropy(trimmed)
    } else {
        // Test if Base32 format (stripped length == 52)
        let stripped: String = trimmed.chars().filter(|c| !c.is_whitespace() && *c != '-').collect();
        if stripped.len() == BASE32_CHAR_COUNT {
            base32_to_entropy(trimmed)
        } else {
            Err(RecoveryCodeError::UnrecognizedFormat)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bip39_generation_and_validation_roundtrip() {
        let code = generate_bip39_recovery_code();
        let words: Vec<&str> = code.split_whitespace().collect();
        assert_eq!(words.len(), 24);

        let entropy = bip39_to_entropy(&code).expect("Valid BIP39 recovery code must decode");
        assert_eq!(entropy.len(), 32);

        // Re-encoding must produce identical phrase
        let re_encoded = entropy_to_bip39(&entropy);
        assert_eq!(re_encoded, code);
    }

    #[test]
    fn test_bip39_checksum_tamper_detection() {
        let code = generate_bip39_recovery_code();
        let mut words: Vec<&str> = code.split_whitespace().collect();

        // Swap the last word with another word from wordlist to corrupt checksum
        let replacement = if words[23] == "abandon" { "ability" } else { "abandon" };
        words[23] = replacement;
        let tampered = words.join(" ");

        let err = bip39_to_entropy(&tampered).unwrap_err();
        assert_eq!(err, RecoveryCodeError::InvalidChecksum);
    }

    #[test]
    fn test_bip39_invalid_word_detection() {
        let code = generate_bip39_recovery_code();
        let mut words: Vec<&str> = code.split_whitespace().collect();
        words[5] = "notabip39word";
        let tampered = words.join(" ");

        let err = bip39_to_entropy(&tampered).unwrap_err();
        match err {
            RecoveryCodeError::WordNotFound(w, pos) => {
                assert_eq!(w, "notabip39word");
                assert_eq!(pos, 6);
            }
            _ => panic!("Expected WordNotFound error"),
        }
    }

    #[test]
    fn test_base32_generation_and_validation_roundtrip() {
        let code = generate_base32_recovery_code();
        assert_eq!(code.len(), 52 + 12); // 52 chars + 12 spaces

        let entropy = base32_to_entropy(&code).expect("Valid Base32 code must decode");
        assert_eq!(entropy.len(), 32);

        let re_encoded = entropy_to_base32(&entropy);
        assert_eq!(re_encoded, code);
    }

    #[test]
    fn test_unified_validator() {
        let bip39 = generate_bip39_recovery_code();
        let base32 = generate_base32_recovery_code();

        assert!(validate_recovery_code(&bip39).is_ok());
        assert!(validate_recovery_code(&base32).is_ok());
        assert!(validate_recovery_code("too short").is_err());
    }
}

