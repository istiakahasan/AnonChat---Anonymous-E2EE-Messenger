//! AnonChat Self-Describing Backup Container Format
//!
//! # Why a Header Is Mandatory:
//! A naive format of `[salt][nonce][ciphertext]` fails silently when Argon2 parameters
//! are updated in the future. The application of the future cannot decrypt the backup
//! of the past because the KDF parameters are hardcoded in the app, not stored in the file.
//! The server stores only the blob; it cannot help.
//! The container file must carry everything needed to decrypt it.
//!
//! # Binary Layout (42-byte header + N-byte ciphertext, little-endian):
//! ```text
//! Offset  Size  Field
//! 0       4     Magic bytes: "ANON" (0x41 0x4E 0x4F 0x4E)
//! 4       1     Format version: 0x01
//! 5       1     KDF identifier: 0x01 = Argon2id
//! 6       1     Argon2 time cost (iterations), uint8
//! 7       1     Argon2 memory exponent: memory_kib = 1 << exponent
//! 8       1     Argon2 parallelism, uint8
//! 9       16    Salt (random per backup)
//! 25      1     Cipher identifier: 0x01 = AES-256-GCM
//! 26      12    Nonce (random per backup)
//! 38      4     Ciphertext length, uint32 LE
//! 42      N     Ciphertext (includes GCM auth tag as final 16 bytes)
//! ```

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use rand_core::{OsRng, RngCore};
use thiserror::Error;

/// Magic bytes identifying an AnonChat backup container ("ANON").
pub const BACKUP_MAGIC: [u8; 4] = [0x41, 0x4E, 0x4F, 0x4E];

/// Current container format version.
pub const BACKUP_VERSION_1: u8 = 0x01;

/// KDF Identifier: Argon2id.
pub const KDF_ID_ARGON2ID: u8 = 0x01;

/// Cipher Identifier: AES-256-GCM.
pub const CIPHER_ID_AES_256_GCM: u8 = 0x01;

/// Length of the cryptographic salt in bytes.
pub const BACKUP_SALT_SIZE: usize = 16;

/// Length of the AES-GCM nonce in bytes.
pub const BACKUP_NONCE_SIZE: usize = 12;

/// Length of the authentication tag in bytes.
pub const BACKUP_TAG_SIZE: usize = 16;

/// Exact size of the container header in bytes.
pub const BACKUP_HEADER_SIZE: usize = 42;

/// Default Argon2id parameters recommended for mobile & desktop backups:
/// - time_cost: 3 iterations
/// - memory_exponent: 16 (1 << 16 = 65,536 KiB = 64 MiB)
/// - parallelism: 4 lanes
pub const DEFAULT_ARGON2_TIME_COST: u8 = 3;
pub const DEFAULT_ARGON2_MEMORY_EXPONENT: u8 = 16;
pub const DEFAULT_ARGON2_PARALLELISM: u8 = 4;

#[derive(Error, Debug, PartialEq, Eq)]
pub enum BackupContainerError {
    #[error("Header too short: expected at least 42 bytes, got {0}")]
    HeaderTooShort(usize),
    #[error("Invalid magic bytes: expected 'ANON' (0x414E4F4E), got {0:?}")]
    InvalidMagic([u8; 4]),
    #[error("Unsupported format version: {0:#04x} (supported: 0x01)")]
    UnsupportedVersion(u8),
    #[error("Unsupported KDF identifier: {0:#04x} (supported: 0x01 = Argon2id)")]
    UnsupportedKdf(u8),
    #[error("Unsupported cipher identifier: {0:#04x} (supported: 0x01 = AES-256-GCM)")]
    UnsupportedCipher(u8),
    #[error("Payload truncated: header declared {declared} bytes, but found {actual}")]
    PayloadTruncated { declared: usize, actual: usize },
    #[error("Ciphertext too short: must be at least 16 bytes for GCM auth tag, got {0}")]
    CiphertextTooShort(usize),
    #[error("Decryption failed: integrity check or authentication tag verification failed")]
    DecryptionFailed,
    #[error("Encryption failed")]
    EncryptionFailed,
    #[error("Argon2 memory exponent too large: 1 << {0} exceeds 64-bit address space")]
    MemoryExponentTooLarge(u8),
}

/// Self-describing header representing the first 42 bytes of an AnonChat backup container.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BackupHeader {
    /// Offset 0..4: "ANON" (0x41 0x4E 0x4F 0x4E)
    pub magic: [u8; 4],
    /// Offset 4: Format version (0x01)
    pub version: u8,
    /// Offset 5: KDF identifier (0x01 = Argon2id)
    pub kdf_id: u8,
    /// Offset 6: Argon2 time cost (iterations), uint8
    pub time_cost: u8,
    /// Offset 7: Argon2 memory exponent: memory_kib = 1 << exponent
    pub memory_exponent: u8,
    /// Offset 8: Argon2 parallelism, uint8
    pub parallelism: u8,
    /// Offset 9..25: Salt (16 bytes random per backup)
    pub salt: [u8; BACKUP_SALT_SIZE],
    /// Offset 25: Cipher identifier (0x01 = AES-256-GCM)
    pub cipher_id: u8,
    /// Offset 26..38: Nonce (12 bytes random per backup)
    pub nonce: [u8; BACKUP_NONCE_SIZE],
    /// Offset 38..42: Ciphertext length, uint32 LE
    pub ciphertext_len: u32,
}

impl BackupHeader {
    /// Creates a new default header with cryptographically random salt and nonce.
    pub fn new(ciphertext_len: u32) -> Self {
        Self::with_params(
            DEFAULT_ARGON2_TIME_COST,
            DEFAULT_ARGON2_MEMORY_EXPONENT,
            DEFAULT_ARGON2_PARALLELISM,
            ciphertext_len,
        )
    }

    /// Creates a new header with explicit Argon2id parameters.
    pub fn with_params(
        time_cost: u8,
        memory_exponent: u8,
        parallelism: u8,
        ciphertext_len: u32,
    ) -> Self {
        let mut salt = [0u8; BACKUP_SALT_SIZE];
        let mut nonce = [0u8; BACKUP_NONCE_SIZE];
        OsRng.fill_bytes(&mut salt);
        OsRng.fill_bytes(&mut nonce);

        Self {
            magic: BACKUP_MAGIC,
            version: BACKUP_VERSION_1,
            kdf_id: KDF_ID_ARGON2ID,
            time_cost,
            memory_exponent,
            parallelism,
            salt,
            cipher_id: CIPHER_ID_AES_256_GCM,
            nonce,
            ciphertext_len,
        }
    }

    /// Calculates memory requirement in KiB: `memory_kib = 1 << memory_exponent`.
    pub fn memory_kib(&self) -> Result<u64, BackupContainerError> {
        if self.memory_exponent >= 64 {
            return Err(BackupContainerError::MemoryExponentTooLarge(self.memory_exponent));
        }
        Ok(1u64 << self.memory_exponent)
    }

    /// Serializes the header into its exact 42-byte little-endian binary representation.
    pub fn to_bytes(&self) -> [u8; BACKUP_HEADER_SIZE] {
        let mut bytes = [0u8; BACKUP_HEADER_SIZE];
        bytes[0..4].copy_from_slice(&self.magic);
        bytes[4] = self.version;
        bytes[5] = self.kdf_id;
        bytes[6] = self.time_cost;
        bytes[7] = self.memory_exponent;
        bytes[8] = self.parallelism;
        bytes[9..25].copy_from_slice(&self.salt);
        bytes[25] = self.cipher_id;
        bytes[26..38].copy_from_slice(&self.nonce);
        bytes[38..42].copy_from_slice(&self.ciphertext_len.to_le_bytes());
        bytes
    }

    /// Parses and validates a 42-byte binary header.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, BackupContainerError> {
        if bytes.len() < BACKUP_HEADER_SIZE {
            return Err(BackupContainerError::HeaderTooShort(bytes.len()));
        }

        let mut magic = [0u8; 4];
        magic.copy_from_slice(&bytes[0..4]);
        if magic != BACKUP_MAGIC {
            return Err(BackupContainerError::InvalidMagic(magic));
        }

        let version = bytes[4];
        if version != BACKUP_VERSION_1 {
            return Err(BackupContainerError::UnsupportedVersion(version));
        }

        let kdf_id = bytes[5];
        if kdf_id != KDF_ID_ARGON2ID {
            return Err(BackupContainerError::UnsupportedKdf(kdf_id));
        }

        let time_cost = bytes[6];
        let memory_exponent = bytes[7];
        let parallelism = bytes[8];

        let mut salt = [0u8; BACKUP_SALT_SIZE];
        salt.copy_from_slice(&bytes[9..25]);

        let cipher_id = bytes[25];
        if cipher_id != CIPHER_ID_AES_256_GCM {
            return Err(BackupContainerError::UnsupportedCipher(cipher_id));
        }

        let mut nonce = [0u8; BACKUP_NONCE_SIZE];
        nonce.copy_from_slice(&bytes[26..38]);

        let ciphertext_len = u32::from_le_bytes([bytes[38], bytes[39], bytes[40], bytes[41]]);

        Ok(Self {
            magic,
            version,
            kdf_id,
            time_cost,
            memory_exponent,
            parallelism,
            salt,
            cipher_id,
            nonce,
            ciphertext_len,
        })
    }
}

/// Complete AnonChat Backup Container (42-byte header + N-byte ciphertext).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BackupContainer {
    pub header: BackupHeader,
    pub ciphertext: Vec<u8>,
}

impl BackupContainer {
    /// Encrypts plaintext payload with a derived 256-bit AES key and creates the container.
    ///
    /// Cryptographic Invariant:
    /// The entire 42-byte header is used as Additional Authenticated Data (AAD) for AES-256-GCM.
    /// Any tampering with KDF parameters, version, salt, nonce, or ciphertext length
    /// will cause authentication to fail immediately.
    pub fn encrypt(
        key_256: &[u8; 32],
        plaintext: &[u8],
        time_cost: u8,
        memory_exponent: u8,
        parallelism: u8,
    ) -> Result<Self, BackupContainerError> {
        let ciphertext_len = (plaintext.len() + BACKUP_TAG_SIZE) as u32;
        let header = BackupHeader::with_params(time_cost, memory_exponent, parallelism, ciphertext_len);
        let header_bytes = header.to_bytes();

        let cipher = Aes256Gcm::new_from_slice(key_256)
            .map_err(|_| BackupContainerError::EncryptionFailed)?;
        let nonce = Nonce::from_slice(&header.nonce);

        let payload = Payload {
            msg: plaintext,
            aad: &header_bytes,
        };

        let ciphertext = cipher
            .encrypt(nonce, payload)
            .map_err(|_| BackupContainerError::EncryptionFailed)?;

        debug_assert_eq!(ciphertext.len(), ciphertext_len as usize);

        Ok(Self { header, ciphertext })
    }

    /// Decrypts the container ciphertext using the derived 256-bit key.
    /// Validates GCM authentication tag against both ciphertext and the 42-byte header AAD.
    pub fn decrypt(&self, key_256: &[u8; 32]) -> Result<Vec<u8>, BackupContainerError> {
        if self.ciphertext.len() < BACKUP_TAG_SIZE {
            return Err(BackupContainerError::CiphertextTooShort(self.ciphertext.len()));
        }

        let header_bytes = self.header.to_bytes();
        let cipher = Aes256Gcm::new_from_slice(key_256)
            .map_err(|_| BackupContainerError::DecryptionFailed)?;
        let nonce = Nonce::from_slice(&self.header.nonce);

        let payload = Payload {
            msg: &self.ciphertext,
            aad: &header_bytes,
        };

        let plaintext = cipher
            .decrypt(nonce, payload)
            .map_err(|_| BackupContainerError::DecryptionFailed)?;

        Ok(plaintext)
    }

    /// Serializes container into a single contiguous byte buffer:
    /// `[42-byte header] + [N-byte ciphertext]`
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(BACKUP_HEADER_SIZE + self.ciphertext.len());
        out.extend_from_slice(&self.header.to_bytes());
        out.extend_from_slice(&self.ciphertext);
        out
    }

    /// Parses and validates a container from raw file bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, BackupContainerError> {
        if bytes.len() < BACKUP_HEADER_SIZE {
            return Err(BackupContainerError::HeaderTooShort(bytes.len()));
        }

        let header = BackupHeader::from_bytes(&bytes[0..BACKUP_HEADER_SIZE])?;
        let expected_total_len = BACKUP_HEADER_SIZE + header.ciphertext_len as usize;

        if bytes.len() < expected_total_len {
            return Err(BackupContainerError::PayloadTruncated {
                declared: header.ciphertext_len as usize,
                actual: bytes.len() - BACKUP_HEADER_SIZE,
            });
        }

        let ciphertext = bytes[BACKUP_HEADER_SIZE..expected_total_len].to_vec();
        Ok(Self { header, ciphertext })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_backup_header_binary_layout() {
        let header = BackupHeader {
            magic: BACKUP_MAGIC,
            version: 0x01,
            kdf_id: 0x01,
            time_cost: 3,
            memory_exponent: 16,
            parallelism: 4,
            salt: [0x55; 16],
            cipher_id: 0x01,
            nonce: [0x77; 12],
            ciphertext_len: 1024,
        };

        let bytes = header.to_bytes();
        assert_eq!(bytes.len(), 42);

        // Verify exact byte offsets per spec:
        assert_eq!(&bytes[0..4], b"ANON");
        assert_eq!(bytes[4], 0x01); // version
        assert_eq!(bytes[5], 0x01); // kdf_id (Argon2id)
        assert_eq!(bytes[6], 3);    // time_cost
        assert_eq!(bytes[7], 16);   // memory_exponent (1 << 16 = 65536 KiB)
        assert_eq!(bytes[8], 4);    // parallelism
        assert_eq!(&bytes[9..25], &[0x55; 16]); // salt
        assert_eq!(bytes[25], 0x01); // cipher_id (AES-256-GCM)
        assert_eq!(&bytes[26..38], &[0x77; 12]); // nonce
        assert_eq!(&bytes[38..42], &1024u32.to_le_bytes()); // uint32 LE

        // Test memory KiB calculation
        assert_eq!(header.memory_kib().unwrap(), 65536);

        // Test deserialization round-trip
        let parsed = BackupHeader::from_bytes(&bytes).expect("Failed to parse header");
        assert_eq!(parsed, header);
    }

    #[test]
    fn test_backup_container_roundtrip_and_tamper_detection() {
        let key = [0x42u8; 32];
        let plaintext = b"AnonChat encrypted local database backup (SQLCipher + keys)";

        // Encrypt container
        let container = BackupContainer::encrypt(&key, plaintext, 3, 16, 4).unwrap();
        let file_bytes = container.to_bytes();
        assert_eq!(file_bytes.len(), 42 + plaintext.len() + 16);

        // Parse from raw bytes
        let restored_container = BackupContainer::from_bytes(&file_bytes).unwrap();
        assert_eq!(restored_container.header.memory_kib().unwrap(), 65536);

        // Decrypt successfully
        let decrypted = restored_container.decrypt(&key).unwrap();
        assert_eq!(decrypted, plaintext);

        // Tamper test 1: Modify a byte in header (time_cost at offset 6)
        let mut tampered_header = file_bytes.clone();
        tampered_header[6] ^= 0x01; // Change iterations
        let tampered_container = BackupContainer::from_bytes(&tampered_header).unwrap();
        assert_eq!(
            tampered_container.decrypt(&key),
            Err(BackupContainerError::DecryptionFailed),
            "Tampering with KDF parameters must cause GCM AAD verification failure!"
        );

        // Tamper test 2: Modify a byte in ciphertext
        let mut tampered_body = file_bytes.clone();
        tampered_body[50] ^= 0xFF;
        let tampered_container2 = BackupContainer::from_bytes(&tampered_body).unwrap();
        assert_eq!(
            tampered_container2.decrypt(&key),
            Err(BackupContainerError::DecryptionFailed)
        );

        // Tamper test 3: Corrupt magic bytes
        let mut bad_magic = file_bytes.clone();
        bad_magic[0] = b'X';
        assert!(matches!(
            BackupContainer::from_bytes(&bad_magic),
            Err(BackupContainerError::InvalidMagic(_))
        ));
    }
}
