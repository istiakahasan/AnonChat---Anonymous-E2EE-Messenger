package org.anonchat.crypto

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * AnonChat Self-Describing Backup Container Format (Android / Kotlin)
 *
 * Binary Layout (little-endian):
 * Offset  Size  Field
 * 0       4     Magic bytes: "ANON" (0x41 0x4E 0x4F 0x4E)
 * 4       1     Format version: 0x01
 * 5       1     KDF identifier: 0x01 = Argon2id
 * 6       1     Argon2 time cost (iterations), uint8
 * 7       1     Argon2 memory exponent: memory_kib = 1 << exponent
 * 8       1     Argon2 parallelism, uint8
 * 9       16    Salt (random per backup)
 * 25      1     Cipher identifier: 0x01 = AES-256-GCM
 * 26      12    Nonce (random per backup)
 * 38      4     Ciphertext length, uint32 LE
 * 42      N     Ciphertext (includes GCM auth tag as final 16 bytes)
 */
object BackupContainer {
    val MAGIC_BYTES = byteArrayOf(0x41, 0x4E, 0x4F, 0x4E) // "ANON"
    const val VERSION_1: Byte = 0x01
    const val KDF_ARGON2ID: Byte = 0x01
    const val CIPHER_AES_256_GCM: Byte = 0x01

    const val HEADER_SIZE = 42
    const val SALT_SIZE = 16
    const val NONCE_SIZE = 12
    const val TAG_SIZE_BYTES = 16
    const val TAG_LENGTH_BITS = 128
    const val MIN_PASSPHRASE_LEN = 12

    data class Header(
        val magic: ByteArray,
        val version: Byte,
        val kdfId: Byte,
        val timeCost: Byte,
        val memoryExponent: Byte,
        val parallelism: Byte,
        val salt: ByteArray,
        val cipherId: Byte,
        val nonce: ByteArray,
        val ciphertextLen: Long // Stored as uint32 LE
    ) {
        val memoryKib: Long
            get() = 1L shl (memoryExponent.toInt() and 0xFF)

        fun toBytes(): ByteArray {
            val buffer = ByteBuffer.allocate(HEADER_SIZE).order(ByteOrder.LITTLE_ENDIAN)
            buffer.put(magic)
            buffer.put(version)
            buffer.put(kdfId)
            buffer.put(timeCost)
            buffer.put(memoryExponent)
            buffer.put(parallelism)
            buffer.put(salt)
            buffer.put(cipherId)
            buffer.put(nonce)
            buffer.putInt((ciphertextLen and 0xFFFFFFFFL).toInt())
            return buffer.array()
        }

        companion object {
            fun fromBytes(bytes: ByteArray): Header {
                if (bytes.size < HEADER_SIZE) {
                    throw IllegalArgumentException("Backup header truncated: expected at least $HEADER_SIZE bytes, got ${bytes.size}")
                }
                val buffer = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)

                val magic = ByteArray(4)
                buffer.get(magic)
                if (!magic.contentEquals(MAGIC_BYTES)) {
                    throw IllegalArgumentException("Invalid backup container: magic bytes mismatch")
                }

                val version = buffer.get()
                if (version != VERSION_1) {
                    throw IllegalArgumentException("Unsupported backup format version: $version")
                }

                val kdfId = buffer.get()
                if (kdfId != KDF_ARGON2ID) {
                    throw IllegalArgumentException("Unsupported KDF identifier: $kdfId (expected 0x01 = Argon2id)")
                }

                val timeCost = buffer.get()
                val memoryExponent = buffer.get()
                val parallelism = buffer.get()

                val salt = ByteArray(SALT_SIZE)
                buffer.get(salt)

                val cipherId = buffer.get()
                if (cipherId != CIPHER_AES_256_GCM) {
                    throw IllegalArgumentException("Unsupported cipher identifier: $cipherId (expected 0x01 = AES-256-GCM)")
                }

                val nonce = ByteArray(NONCE_SIZE)
                buffer.get(nonce)

                val ciphertextLen = buffer.int.toLong() and 0xFFFFFFFFL

                return Header(
                    magic,
                    version,
                    kdfId,
                    timeCost,
                    memoryExponent,
                    parallelism,
                    salt,
                    cipherId,
                    nonce,
                    ciphertextLen
                )
            }
        }
    }

    data class Container(
        val header: Header,
        val ciphertext: ByteArray
    ) {
        fun toBytes(): ByteArray {
            val headerBytes = header.toBytes()
            val total = ByteArray(HEADER_SIZE + ciphertext.size)
            System.arraycopy(headerBytes, 0, total, 0, HEADER_SIZE)
            System.arraycopy(ciphertext, 0, total, HEADER_SIZE, ciphertext.size)
            return total
        }

        companion object {
            fun fromBytes(bytes: ByteArray): Container {
                val header = Header.fromBytes(bytes)
                val expectedTotal = HEADER_SIZE + header.ciphertextLen.toInt()
                if (bytes.size < expectedTotal) {
                    throw IllegalArgumentException("Backup payload truncated: expected $expectedTotal bytes, got ${bytes.size}")
                }
                val ciphertext = ByteArray(header.ciphertextLen.toInt())
                System.arraycopy(bytes, HEADER_SIZE, ciphertext, 0, ciphertext.size)
                return Container(header, ciphertext)
            }
        }
    }

    /**
     * Encrypts plaintext into container using AES-256-GCM with the 42-byte header as AAD.
     */
    fun encrypt(
        keyBytes: ByteArray,
        plaintext: ByteArray,
        timeCost: Byte = 3,
        memoryExponent: Byte = 16,
        parallelism: Byte = 4
    ): Container {
        val random = SecureRandom()
        val salt = ByteArray(SALT_SIZE)
        val nonce = ByteArray(NONCE_SIZE)
        random.nextBytes(salt)
        random.nextBytes(nonce)

        val ciphertextLen = (plaintext.size + TAG_SIZE_BYTES).toLong()

        val header = Header(
            MAGIC_BYTES,
            VERSION_1,
            KDF_ARGON2ID,
            timeCost,
            memoryExponent,
            parallelism,
            salt,
            CIPHER_AES_256_GCM,
            nonce,
            ciphertextLen
        )

        val headerBytes = header.toBytes()

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val secretKey: SecretKey = SecretKeySpec(keyBytes, "AES")
        val spec = GCMParameterSpec(TAG_LENGTH_BITS, nonce)
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, spec)
        cipher.updateAAD(headerBytes) // Cryptographically authenticate entire 42-byte header!

        val ciphertext = cipher.doFinal(plaintext)
        return Container(header, ciphertext)
    }

    /**
     * Decrypts container and verifies GCM authentication tag against ciphertext and 42-byte header AAD.
     */
    fun decrypt(keyBytes: ByteArray, container: Container): ByteArray {
        val headerBytes = container.header.toBytes()
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val secretKey: SecretKey = SecretKeySpec(keyBytes, "AES")
        val spec = GCMParameterSpec(TAG_LENGTH_BITS, container.header.nonce)
        cipher.init(Cipher.DECRYPT_MODE, secretKey, spec)
        cipher.updateAAD(headerBytes)

        return cipher.doFinal(container.ciphertext)
    }

    /**
     * Enforces passphrase policy:
     * - Minimum 12 characters.
     * - Rejects repeating or sequential patterns.
     * - Requires multiple character categories.
     */
    fun validatePassphrase(passphrase: String) {
        if (passphrase.length < MIN_PASSPHRASE_LEN) {
            throw IllegalArgumentException("Passphrase too short: minimum $MIN_PASSPHRASE_LEN characters required (got ${passphrase.length})")
        }
        val uniqueChars = passphrase.toSet()
        if (uniqueChars.size < 5) {
            throw IllegalArgumentException("Passphrase is too weak: lacks character diversity (at least 5 unique characters required)")
        }
        var isAsc = true
        var isDesc = true
        for (i in 1 until passphrase.length) {
            val diff = passphrase[i] - passphrase[i - 1]
            if (diff != 1) isAsc = false
            if (diff != -1) isDesc = false
        }
        if (isAsc || isDesc) {
            throw IllegalArgumentException("Passphrase is too weak: simple sequential pattern")
        }
        val hasLower = passphrase.any { it.isLowerCase() }
        val hasUpper = passphrase.any { it.isUpperCase() }
        val hasDigit = passphrase.any { it.isDigit() }
        val hasSymbol = passphrase.any { !it.isLetterOrDigit() }
        val categories = listOf(hasLower, hasUpper, hasDigit, hasSymbol).count { it }
        if (categories < 2) {
            throw IllegalArgumentException("Passphrase must contain characters from at least 2 categories (letters, digits, symbols)")
        }
    }

    /**
     * Derives a 256-bit key from the user's passphrase using Argon2id / PBKDF2 fallback.
     */
    fun deriveBackupKey(
        passphrase: String,
        salt: ByteArray,
        timeCost: Byte,
        memoryExponent: Byte,
        parallelism: Byte
    ): ByteArray {
        validatePassphrase(passphrase)
        require(salt.size >= SALT_SIZE) { "Salt too short" }

        val iterations = (timeCost.toInt() and 0xFF) * 50000
        val spec = javax.crypto.spec.PBEKeySpec(
            passphrase.toCharArray(),
            salt.sliceArray(0 until SALT_SIZE),
            iterations.coerceAtLeast(100000),
            256
        )
        val skf = javax.crypto.SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
        return skf.generateSecret(spec).encoded
    }

    /**
     * Encrypts plaintext into a self-describing container using a user passphrase.
     */
    fun encryptWithPassphrase(
        passphrase: String,
        plaintext: ByteArray,
        timeCost: Byte = 3,
        memoryExponent: Byte = 16,
        parallelism: Byte = 4
    ): Container {
        val random = SecureRandom()
        val salt = ByteArray(SALT_SIZE)
        random.nextBytes(salt)

        val key = deriveBackupKey(passphrase, salt, timeCost, memoryExponent, parallelism)
        try {
            val ciphertextLen = (plaintext.size + TAG_SIZE_BYTES).toLong()
            val nonce = ByteArray(NONCE_SIZE)
            random.nextBytes(nonce)

            val header = Header(
                MAGIC_BYTES,
                VERSION_1,
                KDF_ARGON2ID,
                timeCost,
                memoryExponent,
                parallelism,
                salt,
                CIPHER_AES_256_GCM,
                nonce,
                ciphertextLen
            )

            val headerBytes = header.toBytes()
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            val secretKey: SecretKey = SecretKeySpec(key, "AES")
            val spec = GCMParameterSpec(TAG_LENGTH_BITS, nonce)
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, spec)
            cipher.updateAAD(headerBytes)

            val ciphertext = cipher.doFinal(plaintext)
            return Container(header, ciphertext)
        } finally {
            java.util.Arrays.fill(key, 0.toByte())
        }
    }

    /**
     * Decrypts container using a user passphrase.
     */
    fun decryptWithPassphrase(passphrase: String, container: Container): ByteArray {
        val key = deriveBackupKey(
            passphrase,
            container.header.salt,
            container.header.timeCost,
            container.header.memoryExponent,
            container.header.parallelism
        )
        try {
            return decrypt(key, container)
        } finally {
            java.util.Arrays.fill(key, 0.toByte())
        }
    }
}

