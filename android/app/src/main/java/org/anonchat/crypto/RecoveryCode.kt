package org.anonchat.crypto

import java.security.MessageDigest
import java.security.SecureRandom

/**
 * High-Entropy Recovery Code Implementation (Android / Kotlin)
 *
 * Implements:
 * - Option B (Recommended): 24-word BIP39 mnemonic phrase (256-bit entropy + 8-bit SHA-256 checksum)
 * - Option A: Crockford Base32 52-character recovery code in 13 groups of 4 separated by spaces
 */
object RecoveryCode {
    const val CROCKFORD_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

    /**
     * Generates 256 bits (32 bytes) of cryptographically secure random entropy.
     */
    fun generateEntropy256(): ByteArray {
        val entropy = ByteArray(32)
        SecureRandom().nextBytes(entropy)
        return entropy
    }

    private fun sha256(data: ByteArray): ByteArray {
        val md = MessageDigest.getInstance("SHA-256")
        return md.digest(data)
    }

    /**
     * Encodes 32-byte (256-bit) entropy into a 24-word BIP39 mnemonic phrase.
     */
    fun entropyToBip39(entropy: ByteArray): String {
        require(entropy.size == 32) { "Invalid entropy length: expected 32 bytes, got ${entropy.size}" }

        // 1. Calculate 8-bit checksum: first byte of SHA-256(entropy)
        val hash = sha256(entropy)
        val checksum = hash[0].toInt() and 0xFF

        // 2. Build 264-bit stream
        val bits = BooleanArray(264)
        for (i in entropy.indices) {
            val byte = entropy[i].toInt() and 0xFF
            for (bitIdx in 7 downTo 0) {
                bits[i * 8 + (7 - bitIdx)] = ((byte shr bitIdx) and 1) == 1
            }
        }
        for (bitIdx in 7 downTo 0) {
            bits[256 + (7 - bitIdx)] = ((checksum shr bitIdx) and 1) == 1
        }

        // 3. Extract 24 chunks of 11 bits each
        val words = mutableListOf<String>()
        for (i in 0 until 24) {
            var wordIdx = 0
            for (bitOffset in 0 until 11) {
                val bitVal = if (bits[i * 11 + bitOffset]) 1 else 0
                wordIdx = (wordIdx shl 1) or bitVal
            }
            words.add(Bip39Words.WORDS[wordIdx])
        }

        return words.joinToString(" ")
    }

    /**
     * Decodes and validates a 24-word BIP39 mnemonic phrase, recovering 32-byte entropy.
     */
    fun bip39ToEntropy(phrase: String): ByteArray {
        val words = phrase.trim().lowercase().split("\\s+".toRegex()).filter { it.isNotEmpty() }
        require(words.size == 24) { "Invalid word count: expected 24 words, got ${words.size}" }

        val bits = BooleanArray(264)
        for (i in words.indices) {
            val word = words[i]
            val wordIdx = Bip39Words.WORDS.indexOf(word)
            require(wordIdx >= 0) { "Word not found in BIP39 wordlist: '$word' at position ${i + 1}" }
            for (bitIdx in 10 downTo 0) {
                bits[i * 11 + (10 - bitIdx)] = ((wordIdx shr bitIdx) and 1) == 1
            }
        }

        // Extract 32-byte entropy
        val entropy = ByteArray(32)
        for (byteIdx in 0 until 32) {
            var byte = 0
            for (bitOffset in 0 until 8) {
                val bitVal = if (bits[byteIdx * 8 + bitOffset]) 1 else 0
                byte = (byte shl 1) or bitVal
            }
            entropy[byteIdx] = byte.toByte()
        }

        // Extract 8-bit checksum
        var expectedChecksum = 0
        for (bitOffset in 0 until 8) {
            val bitVal = if (bits[256 + bitOffset]) 1 else 0
            expectedChecksum = (expectedChecksum shl 1) or bitVal
        }

        // Verify checksum
        val hash = sha256(entropy)
        val actualChecksum = hash[0].toInt() and 0xFF
        require(actualChecksum == expectedChecksum) {
            "Invalid BIP39 checksum: phrase may be mistyped or corrupted"
        }

        return entropy
    }

    /**
     * Generates a fresh 24-word BIP39 recovery code (Option B - Recommended).
     */
    fun generateBip39RecoveryCode(): String {
        return entropyToBip39(generateEntropy256())
    }

    /**
     * Encodes 32-byte (256-bit) entropy into Crockford Base32 (Option A: 52 characters in groups of 4).
     */
    fun entropyToBase32(entropy: ByteArray): String {
        require(entropy.size == 32) { "Invalid entropy length: expected 32 bytes, got ${entropy.size}" }

        val bits = BooleanArray(260)
        for (i in entropy.indices) {
            val byte = entropy[i].toInt() and 0xFF
            for (bitIdx in 7 downTo 0) {
                bits[i * 8 + (7 - bitIdx)] = ((byte shr bitIdx) and 1) == 1
            }
        }
        // 4 trailing zero padding bits (already false)

        val chars = StringBuilder()
        for (i in 0 until 52) {
            var valIdx = 0
            for (bitOffset in 0 until 5) {
                val bitVal = if (bits[i * 5 + bitOffset]) 1 else 0
                valIdx = (valIdx shl 1) or bitVal
            }
            chars.append(CROCKFORD_ALPHABET[valIdx])
        }

        // Format into 13 groups of 4 separated by spaces
        val groups = mutableListOf<String>()
        for (i in 0 until 52 step 4) {
            groups.add(chars.substring(i, i + 4))
        }
        return groups.joinToString(" ")
    }

    /**
     * Decodes Crockford Base32 recovery code into 32-byte entropy.
     */
    fun base32ToEntropy(code: String): ByteArray {
        var normalized = code.replace("[\\s-]+".toRegex(), "").uppercase()
        normalized = normalized.replace('O', '0').replace('I', '1').replace('L', '1')

        require(normalized.length == 52) {
            "Invalid Base32 length: expected 52 characters, got ${normalized.length}"
        }

        val bits = BooleanArray(260)
        for (i in normalized.indices) {
            val c = normalized[i]
            val idx = CROCKFORD_ALPHABET.indexOf(c)
            require(idx >= 0) { "Invalid Base32 character: '$c'" }
            for (bitIdx in 4 downTo 0) {
                bits[i * 5 + (4 - bitIdx)] = ((idx shr bitIdx) and 1) == 1
            }
        }

        val entropy = ByteArray(32)
        for (byteIdx in 0 until 32) {
            var byte = 0
            for (bitOffset in 0 until 8) {
                val bitVal = if (bits[byteIdx * 8 + bitOffset]) 1 else 0
                byte = (byte shl 1) or bitVal
            }
            entropy[byteIdx] = byte.toByte()
        }

        return entropy
    }

    /**
     * Generates a fresh Crockford Base32 recovery code (Option A: 52 characters in 13 groups of 4).
     */
    fun generateBase32RecoveryCode(): String {
        return entropyToBase32(generateEntropy256())
    }

    /**
     * Validates any recovery code (BIP39 24 words or Base32 52 characters).
     */
    fun validateRecoveryCode(input: String): ByteArray {
        val trimmed = input.trim()
        val words = trimmed.split("\\s+".toRegex()).filter { it.isNotEmpty() }
        if (words.size == 24) {
            return bip39ToEntropy(trimmed)
        }

        val stripped = trimmed.replace("[\\s-]+".toRegex(), "")
        if (stripped.length == 52) {
            return base32ToEntropy(trimmed)
        }

        throw IllegalArgumentException("Unrecognized recovery code format: must be 24 BIP39 words or 52 Base32 characters")
    }
}

