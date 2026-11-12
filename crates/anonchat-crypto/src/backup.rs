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
    Aes256Gcm, Key, Nonce,
};
use argon2::{Algorithm, Argon2, Params, Version};
use rand_core::{OsRng, RngCore};
use thiserror::Error;
use zeroize::Zeroizing;

/// Minimum passphrase length required to derive backup keys (enforces strong security).
pub const MIN_PASSPHRASE_LEN: usize = 12;

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

/// Size of the Additional Authenticated Data (AAD): offsets 0 to 37 (38 bytes total).
/// Encompasses magic, version, kdf_id, time_cost, memory_exponent, parallelism, salt, cipher_id, and nonce
/// (everything before the ciphertext length field).
pub const BACKUP_AAD_SIZE: usize = 38;

/// Default Argon2id parameters recommended for mobile & desktop backups:
/// - time_cost: 3 iterations
/// - memory_exponent: 16 (1 << 16 = 65,536 KiB = 64 MiB)
/// - parallelism: 4 lanes
pub const DEFAULT_ARGON2_TIME_COST: u8 = 3;
pub const DEFAULT_ARGON2_MEMORY_EXPONENT: u8 = 16;
pub const DEFAULT_ARGON2_PARALLELISM: u8 = 4;

/// Resource Exhaustion Defense Ceilings (Sub-Step 3.4):
/// Prevents a malicious backup header specifying exorbitant Argon2 parameters
/// from causing a Denial-of-Service / Out-Of-Memory condition on the device.
pub const MAX_ALLOWED_MEMORY_EXPONENT: u8 = 20; // 1 << 20 KiB = 1,048,576 KiB = 1 GiB
pub const MAX_ALLOWED_TIME_COST: u8 = 10;
pub const MAX_ALLOWED_PARALLELISM: u8 = 4;

/// Default block size for post-encryption backup padding (64 KiB = 65,536 bytes) (Sub-Step 6.1).
pub const DEFAULT_BACKUP_BLOCK_SIZE: usize = 65536;

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
    #[error("Incorrect passphrase or corrupted backup file.")]
    DecryptionFailed,
    #[error("Encryption failed")]
    EncryptionFailed,
    #[error("Argon2 memory exponent too large: 1 << {0} exceeds 64-bit address space")]
    MemoryExponentTooLarge(u8),
    #[error("Argon2 parameter exceeds security ceiling: memory_exponent {0} > {MAX_ALLOWED_MEMORY_EXPONENT} (resource exhaustion defense)")]
    MemoryExponentExceedsCeiling(u8),
    #[error("Argon2 parameter exceeds security ceiling: time_cost {0} > {MAX_ALLOWED_TIME_COST} (resource exhaustion defense)")]
    TimeCostExceedsCeiling(u8),
    #[error("Argon2 parameter exceeds security ceiling: parallelism {0} > {MAX_ALLOWED_PARALLELISM} (resource exhaustion defense)")]
    ParallelismExceedsCeiling(u8),
    #[error("Passphrase too short: minimum {MIN_PASSPHRASE_LEN} characters required, got {0}")]
    PassphraseTooShort(usize),
    #[error("Passphrase is too weak: {0}")]
    WeakPassphrase(String),
    #[error("Argon2 key derivation error: {0}")]
    KdfError(String),
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

    /// Resource Exhaustion Defense:
    /// Enforces maximum ceilings on KDF parameters before derivation:
    /// - Reject memory_exponent > 20 (1 GiB)
    /// - Reject time_cost > 10
    /// - Reject parallelism > 4
    pub fn validate_resource_limits(&self) -> Result<(), BackupContainerError> {
        if self.memory_exponent > MAX_ALLOWED_MEMORY_EXPONENT {
            return Err(BackupContainerError::MemoryExponentExceedsCeiling(
                self.memory_exponent,
            ));
        }
        if self.time_cost > MAX_ALLOWED_TIME_COST {
            return Err(BackupContainerError::TimeCostExceedsCeiling(self.time_cost));
        }
        if self.parallelism > MAX_ALLOWED_PARALLELISM {
            return Err(BackupContainerError::ParallelismExceedsCeiling(
                self.parallelism,
            ));
        }
        Ok(())
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

    /// Extracts the 38-byte AAD representation: header bytes from offset 0 to 37
    /// (everything before the ciphertext length field).
    /// Used by AES-256-GCM to bind header parameters to the ciphertext.
    pub fn aad_bytes(&self) -> [u8; BACKUP_AAD_SIZE] {
        let mut aad = [0u8; BACKUP_AAD_SIZE];
        aad[0..4].copy_from_slice(&self.magic);
        aad[4] = self.version;
        aad[5] = self.kdf_id;
        aad[6] = self.time_cost;
        aad[7] = self.memory_exponent;
        aad[8] = self.parallelism;
        aad[9..25].copy_from_slice(&self.salt);
        aad[25] = self.cipher_id;
        aad[26..38].copy_from_slice(&self.nonce);
        aad
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

        let header = Self {
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
        };

        // Resource exhaustion ceiling defense: validate parameters before Argon2 allocation
        header.validate_resource_limits()?;

        Ok(header)
    }
}

/// Enforces strong passphrase policies before key derivation:
/// - High-entropy recovery codes (24 BIP39 words or 52 Base32 chars) automatically pass (256-bit entropy).
/// - For custom passphrases: minimum 12 characters.
/// - Rejects identical repeating characters (e.g. "aaaaaaaaaaaa").
/// - Rejects simple monotonic digit or letter sequences.
/// - Requires at least 5 unique characters and diversity across character classes.
pub fn validate_passphrase(passphrase: &str) -> Result<(), BackupContainerError> {
    // If the input is a valid high-entropy recovery code, it satisfies 256-bit security immediately
    if crate::recovery_code::validate_recovery_code(passphrase).is_ok() {
        return Ok(());
    }

    if passphrase.len() < MIN_PASSPHRASE_LEN {
        return Err(BackupContainerError::PassphraseTooShort(passphrase.len()));
    }

    // Check unique character count
    let mut unique_chars = std::collections::HashSet::new();
    let mut has_lower = false;
    let mut has_upper = false;
    let mut has_digit = false;
    let mut has_other = false;

    for ch in passphrase.chars() {
        unique_chars.insert(ch);
        if ch.is_ascii_lowercase() {
            has_lower = true;
        } else if ch.is_ascii_uppercase() {
            has_upper = true;
        } else if ch.is_ascii_digit() {
            has_digit = true;
        } else {
            has_other = true;
        }
    }

    if unique_chars.len() < 5 {
        return Err(BackupContainerError::WeakPassphrase(
            "Passphrase lacks diversity (at least 5 unique characters required)".into(),
        ));
    }

    // Reject monotonic sequences like "123456789012" or "abcdefghijkl"
    let bytes = passphrase.as_bytes();
    let mut is_monotonic_asc = true;
    let mut is_monotonic_desc = true;
    for i in 1..bytes.len() {
        if bytes[i] as i32 - bytes[i - 1] as i32 != 1 {
            is_monotonic_asc = false;
        }
        if bytes[i - 1] as i32 - bytes[i] as i32 != 1 {
            is_monotonic_desc = false;
        }
    }
    if is_monotonic_asc || is_monotonic_desc {
        return Err(BackupContainerError::WeakPassphrase(
            "Passphrase is a simple sequential pattern".into(),
        ));
    }

    let categories = (has_lower as u8) + (has_upper as u8) + (has_digit as u8) + (has_other as u8);
    if categories < 2 {
        return Err(BackupContainerError::WeakPassphrase(
            "Passphrase must contain at least 2 character categories (letters, digits, or symbols)".into(),
        ));
    }

    Ok(())
}

/// Derives a 256-bit key from the user's passphrase using Argon2id.
///
/// # Inputs:
/// - `passphrase`: string, UTF-8 encoded to bytes. Enforces validation before derivation.
/// - `salt`: 16 random bytes from a cryptographically secure RNG. Fresh salt per backup.
/// - `m_cost_kib`: memory_kib = 1 << memory_exponent (from container header).
/// - `t_cost`: time cost (iterations).
/// - `p_cost`: parallelism (lanes).
///
/// # Output:
/// - 32-byte key wrapped in `Zeroizing` for automatic zeroization on drop.
pub fn derive_backup_key(
    passphrase: &str,
    salt: &[u8],
    m_cost_kib: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<Zeroizing<[u8; 32]>, BackupContainerError> {
    validate_passphrase(passphrase)?;

    // Resource Exhaustion Defense: enforce parameter ceilings before Argon2 derivation
    let max_kib = 1u32 << MAX_ALLOWED_MEMORY_EXPONENT;
    if m_cost_kib > max_kib {
        return Err(BackupContainerError::MemoryExponentExceedsCeiling(
            MAX_ALLOWED_MEMORY_EXPONENT + 1,
        ));
    }
    if t_cost > MAX_ALLOWED_TIME_COST as u32 {
        return Err(BackupContainerError::TimeCostExceedsCeiling(t_cost as u8));
    }
    if p_cost > MAX_ALLOWED_PARALLELISM as u32 {
        return Err(BackupContainerError::ParallelismExceedsCeiling(p_cost as u8));
    }

    if salt.len() < BACKUP_SALT_SIZE {
        return Err(BackupContainerError::KdfError(format!(
            "Salt too short: expected {} bytes, got {}",
            BACKUP_SALT_SIZE,
            salt.len()
        )));
    }

    let params = Params::new(m_cost_kib, t_cost, p_cost, Some(32))
        .map_err(|e| BackupContainerError::KdfError(e.to_string()))?;

    let mut key = Zeroizing::new([0u8; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(passphrase.as_bytes(), &salt[0..BACKUP_SALT_SIZE], &mut *key)
        .map_err(|e| BackupContainerError::KdfError(e.to_string()))?;

    Ok(key)
}

/// Derives a 256-bit (32-byte) key directly from a high-entropy recovery code:
/// `key = Argon2id(recoveryCode, salt, memory, iterations, parallelism, 32)`
pub fn derive_backup_key_from_recovery_code(
    recovery_code: &str,
    salt: &[u8],
    m_cost_kib: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<Zeroizing<[u8; 32]>, BackupContainerError> {
    crate::recovery_code::validate_recovery_code(recovery_code)
        .map_err(|e| BackupContainerError::WeakPassphrase(e.to_string()))?;
    derive_backup_key(recovery_code, salt, m_cost_kib, t_cost, p_cost)
}

/// Helper to derive a 256-bit key directly from a `BackupHeader`.
pub fn derive_key_from_header(
    passphrase: &str,
    header: &BackupHeader,
) -> Result<Zeroizing<[u8; 32]>, BackupContainerError> {
    header.validate_resource_limits()?;
    let m_cost_kib = header.memory_kib()? as u32;
    derive_backup_key(
        passphrase,
        &header.salt,
        m_cost_kib,
        header.time_cost as u32,
        header.parallelism as u32,
    )
}

/// Encrypts the serialized backup payload with AES-256-GCM (Sub-Step 3.3).
///
/// # Inputs:
/// - `plaintext`: the serialized backup bytes (from Sub-Step 3.1).
/// - `key`: 32-byte derived key (from Sub-Step 3.2).
/// - `nonce`: 12 random bytes, fresh for every encryption. Never reuse a nonce with the same key.
/// - `aad`: the header bytes from offset 0 to 37 (everything before the ciphertext length field).
///   This binds the header parameters to the ciphertext and detects tampering.
///
/// Output includes the 16-byte GCM authentication tag at the end.
pub fn encrypt_payload(
    plaintext: &[u8],
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
) -> Result<Vec<u8>, BackupContainerError> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| BackupContainerError::EncryptionFailed)?;
    Ok(ciphertext)
}

/// Decrypts the backup payload with AES-256-GCM, verifying the AAD.
pub fn decrypt_payload(
    ciphertext: &[u8],
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
) -> Result<Vec<u8>, BackupContainerError> {
    if ciphertext.len() < BACKUP_TAG_SIZE {
        return Err(BackupContainerError::CiphertextTooShort(ciphertext.len()));
    }
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| BackupContainerError::DecryptionFailed)?;
    Ok(plaintext)
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
    /// Header bytes 0..37 (everything before ciphertext length) are used as AAD for AES-256-GCM.
    /// Any tampering with KDF parameters, version, salt, cipher_id, or nonce
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
        let aad = header.aad_bytes();

        let ciphertext = encrypt_payload(plaintext, key_256, &header.nonce, &aad)?;
        debug_assert_eq!(ciphertext.len(), ciphertext_len as usize);

        Ok(Self { header, ciphertext })
    }

    /// Decrypts the container ciphertext using the derived 256-bit key.
    /// Validates GCM authentication tag against both ciphertext and the 38-byte header AAD.
    pub fn decrypt(&self, key_256: &[u8; 32]) -> Result<Vec<u8>, BackupContainerError> {
        let aad = self.header.aad_bytes();
        decrypt_payload(&self.ciphertext, key_256, &self.header.nonce, &aad)
    }

    /// Encrypts plaintext payload using a user passphrase.
    ///
    /// 1. Validates passphrase strength (minimum length & entropy).
    /// 2. Generates a fresh 16-byte random salt and 12-byte nonce.
    /// 3. Derives 256-bit AES key using Argon2id with memory_kib = 1 << memory_exponent.
    /// 4. Authenticates header bytes 0..37 as AES-256-GCM AAD.
    /// 5. Automatically zeroizes the derived key on completion.
    pub fn encrypt_with_passphrase(
        passphrase: &str,
        plaintext: &[u8],
        time_cost: u8,
        memory_exponent: u8,
        parallelism: u8,
    ) -> Result<Self, BackupContainerError> {
        let ciphertext_len = (plaintext.len() + BACKUP_TAG_SIZE) as u32;
        let header = BackupHeader::with_params(time_cost, memory_exponent, parallelism, ciphertext_len);

        let m_cost_kib = header.memory_kib()? as u32;
        let key = derive_backup_key(
            passphrase,
            &header.salt,
            m_cost_kib,
            time_cost as u32,
            parallelism as u32,
        )?;

        let aad = header.aad_bytes();
        let ciphertext = encrypt_payload(plaintext, &*key, &header.nonce, &aad)?;

        Ok(Self { header, ciphertext })
    }

    /// Decrypts container payload using the user passphrase.
    ///
    /// Extracts Argon2id parameters (time_cost, memory_exponent, parallelism, salt) from the
    /// 42-byte header, derives the 256-bit key, and decrypts the ciphertext verifying
    /// the full header as AAD.
    pub fn decrypt_with_passphrase(&self, passphrase: &str) -> Result<Vec<u8>, BackupContainerError> {
        let key = derive_key_from_header(passphrase, &self.header)?;
        self.decrypt(&*key)
    }

    /// Serializes container into a single contiguous byte buffer:
    /// `[42-byte header] + [N-byte ciphertext]`
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(BACKUP_HEADER_SIZE + self.ciphertext.len());
        out.extend_from_slice(&self.header.to_bytes());
        out.extend_from_slice(&self.ciphertext);
        out
    }

    /// Serializes container into a single contiguous byte buffer with post-encryption fixed-block padding:
    /// `[42-byte header] + [N-byte ciphertext] + [padding zeroes to block_size]`
    ///
    /// Hardening against size-based side-channel attacks (Sub-Step 6.1):
    /// Pads the entire file to a multiple of `block_size` (default: 64 KiB) using 0x00 zeroes.
    pub fn to_padded_bytes(&self, block_size: usize) -> Vec<u8> {
        pad_to_block_size(self.to_bytes(), block_size)
    }

    /// Parses and validates a container from raw file bytes.
    /// Trailing post-encryption padding bytes are safely ignored using `header.ciphertext_len`.
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

/// Pads encrypted backup container bytes to a fixed block size (Sub-Step 6.1).
///
/// # Security Principle:
/// The ciphertext size must not leak information about plaintext content.
/// After producing `header || ciphertext`, pads the entire file to a fixed block size.
/// Always pads at least 1 byte (up to `block_size`), even if data is already aligned,
/// avoiding any leakage of exact file size.
pub fn pad_to_block_size(data: Vec<u8>, block_size: usize) -> Vec<u8> {
    assert!(block_size > 0, "block_size must be positive");
    let pad_len = block_size - (data.len() % block_size);
    // Always pad, even if already aligned, to avoid leaking exact size
    let pad_len = if pad_len == 0 { block_size } else { pad_len };
    let mut padded = data;
    padded.extend(std::iter::repeat(0x00).take(pad_len));
    padded
}

/// Convenience function to pad backup bytes to the default 64 KiB block size.
pub fn pad_backup(data: Vec<u8>) -> Vec<u8> {
    pad_to_block_size(data, DEFAULT_BACKUP_BLOCK_SIZE)
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

    #[test]
    fn test_passphrase_validation_and_argon2id_derivation() {
        // Test short passphrase rejection (< 12 chars)
        assert_eq!(
            validate_passphrase("short123"),
            Err(BackupContainerError::PassphraseTooShort(8))
        );

        // Test weak repeating passphrase rejection
        assert_eq!(
            validate_passphrase("aaaaaaaaaaaa"),
            Err(BackupContainerError::WeakPassphrase(
                "Passphrase lacks diversity (at least 5 unique characters required)".into()
            ))
        );

        // Test monotonic sequence rejection
        assert_eq!(
            validate_passphrase("123456789012"),
            Err(BackupContainerError::WeakPassphrase(
                "Passphrase lacks diversity (at least 5 unique characters required)".into()
            ))
        );

        // Valid strong passphrase
        let valid_passphrase = "Correct-Horse-Battery-Staple-2026!";
        assert!(validate_passphrase(valid_passphrase).is_ok());

        // Test key derivation with Argon2id parameters
        let salt = [0x99u8; 16];
        let key1 = derive_backup_key(valid_passphrase, &salt, 64, 1, 1).unwrap();
        let key2 = derive_backup_key(valid_passphrase, &salt, 64, 1, 1).unwrap();
        assert_eq!(*key1, *key2, "Argon2id derivation must be deterministic");
        assert_eq!(key1.len(), 32, "Key must be exactly 32 bytes (256 bits)");

        // Different salt produces completely different key
        let salt_diff = [0x88u8; 16];
        let key3 = derive_backup_key(valid_passphrase, &salt_diff, 64, 1, 1).unwrap();
        assert_ne!(*key1, *key3, "Different salts must yield different keys");

        // End-to-end passphrase container encryption and decryption
        let plaintext = b"Confidential SQLite SQLCipher Database Dump";
        let container = BackupContainer::encrypt_with_passphrase(
            valid_passphrase,
            plaintext,
            1,
            6, // 1 << 6 = 64 KiB for fast test execution
            1,
        ).unwrap();

        // Roundtrip to raw file bytes
        let file_bytes = container.to_bytes();
        let restored = BackupContainer::from_bytes(&file_bytes).unwrap();

        // Decrypt with correct passphrase
        let decrypted = restored.decrypt_with_passphrase(valid_passphrase).unwrap();
        assert_eq!(decrypted, plaintext);

        // Decrypt with wrong passphrase fails authentication
        assert_eq!(
            restored.decrypt_with_passphrase("Incorrect-Password-999!"),
            Err(BackupContainerError::DecryptionFailed)
        );
    }

    #[test]
    fn test_pad_to_block_size_always_pads() {
        let block_size = 64;

        // 1. Unaligned data: 50 bytes -> pads 14 bytes of 0x00 to reach 64 bytes
        let data = vec![0x42; 50];
        let padded = pad_to_block_size(data.clone(), block_size);
        assert_eq!(padded.len(), 64);
        assert_eq!(&padded[0..50], &data[..]);
        assert_eq!(&padded[50..64], &[0x00; 14]);

        // 2. Exact multiple of block size (64 bytes): must STILL pad 64 bytes to reach 128 bytes!
        // This invariant ensures an attacker cannot distinguish exact alignments.
        let data_exact = vec![0x42; 64];
        let padded_exact = pad_to_block_size(data_exact.clone(), block_size);
        assert_eq!(padded_exact.len(), 128);
        assert_eq!(&padded_exact[0..64], &data_exact[..]);
        assert_eq!(&padded_exact[64..128], &[0x00; 64]);
    }

    #[test]
    fn test_backup_container_padded_restore() {
        let key = [0x55u8; 32];
        let plaintext = b"Confidential chat database with side-channel padding defense";
        let container = BackupContainer::encrypt(&key, plaintext, 1, 6, 1).unwrap();

        let raw_bytes = container.to_bytes();
        let padded_bytes = container.to_padded_bytes(DEFAULT_BACKUP_BLOCK_SIZE);

        // Padded length is a strict multiple of 64 KiB
        assert_eq!(padded_bytes.len() % DEFAULT_BACKUP_BLOCK_SIZE, 0);
        assert!(padded_bytes.len() > raw_bytes.len());

        // from_bytes parses cleanly by respecting header.ciphertext_len
        let restored_container = BackupContainer::from_bytes(&padded_bytes).unwrap();
        let decrypted = restored_container.decrypt(&key).unwrap();
        assert_eq!(decrypted, plaintext);

        // Tampering with trailing padding zeroes does not corrupt payload decryption
        let mut tampered_padding = padded_bytes.clone();
        let last_idx = tampered_padding.len() - 1;
        tampered_padding[last_idx] ^= 0xFF;
        let restored_tampered = BackupContainer::from_bytes(&tampered_padding).unwrap();
        let decrypted_tampered = restored_tampered.decrypt(&key).unwrap();
        assert_eq!(decrypted_tampered, plaintext);
    }
}

