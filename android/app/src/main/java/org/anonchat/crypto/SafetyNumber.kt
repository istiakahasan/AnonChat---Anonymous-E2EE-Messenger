package org.anonchat.crypto

import java.nio.ByteBuffer
import java.security.MessageDigest

/**
 * Signal Protocol 60-Digit Safety Number Derivation (Android / Kotlin)
 *
 * Algorithm:
 * 1. For each user:
 *    - Initial round: SHA-512(identityKeyBytes + identifier)
 *    - 5,200 iterations of SHA-512(previous_digest + identityKeyBytes)
 *    - Extract 6 groups of 5 digits (30 digits total) using 4-byte big-endian chunks % 100,000.
 * 2. Sort the two 30-digit fingerprints lexicographically.
 * 3. Concatenate the two fingerprints into 60 digits total.
 * 4. Format as 12 groups of 5 digits separated by spaces.
 *
 * Verification State Storage (Local Only):
 * - Persisted in SQLCipher / EncryptedSharedPreferences (never uploaded to relay server).
 * - When remote key changes, verifiedAt is reset to null and a warning is triggered.
 */
object SafetyNumber {
    const val FINGERPRINT_ITERATIONS = 5200

    data class VerificationState(
        val contactId: String,
        val safetyNumber: String,
        val verifiedAt: Long?,
        val lastRemoteKeyHex: String
    )

    /**
     * Computes the 30-digit individual fingerprint using 5,200 SHA-512 iterations.
     */
    fun computeIndividualFingerprint(identityKey: ByteArray, identifier: String): String {
        val md = MessageDigest.getInstance("SHA-512")
        val idBytes = identifier.toByteArray(Charsets.UTF_8)

        // Initial round: SHA-512(identityKey + identifier)
        md.update(identityKey)
        md.update(idBytes)
        var digest = md.digest()

        // 5,200 iterations: SHA-512(digest + identityKey)
        for (i in 0 until FINGERPRINT_ITERATIONS) {
            md.update(digest)
            md.update(identityKey)
            digest = md.digest()
        }

        // Extract 6 groups of 5 digits from 4-byte big-endian chunks % 100,000
        val buffer = ByteBuffer.wrap(digest)
        val sb = java.lang.StringBuilder(30)
        for (i in 0 until 6) {
            val chunk = buffer.int.toLong() and 0xFFFFFFFFL
            val fiveDigits = (chunk % 100000).toString().padStart(5, '0')
            sb.append(fiveDigits)
        }

        return sb.toString()
    }

    /**
     * Derives the full, deterministic 60-digit composite Safety Number for two parties.
     */
    fun generateCompositeSafetyNumber(
        localIdentityKey: ByteArray,
        localIdentifier: String,
        remoteIdentityKey: ByteArray,
        remoteIdentifier: String
    ): String {
        val fpA = computeIndividualFingerprint(localIdentityKey, localIdentifier)
        val fpB = computeIndividualFingerprint(remoteIdentityKey, remoteIdentifier)

        // Lexicographical sort ensures Alice and Bob compute the exact same number
        val sorted = listOf(fpA, fpB).sorted()
        val combined = sorted[0] + sorted[1]

        // Format as 12 groups of 5 digits
        val groups = mutableListOf<String>()
        for (i in 0 until 12) {
            groups.add(combined.substring(i * 5, i * 5 + 5))
        }

        return groups.joinToString(" ")
    }

    /**
     * Checks remote identity key against stored lastRemoteKey.
     * Returns true if key has changed.
     */
    fun checkKeyChanged(currentKeyHex: String, storedState: VerificationState?): Boolean {
        if (storedState == null) return false
        return storedState.lastRemoteKeyHex != currentKeyHex
    }

    /**
     * Step 1: Set verifiedAt = null in local storage when identity key change is detected.
     */
    fun resetVerification(storedState: VerificationState, newKeyHex: String? = null): VerificationState {
        return storedState.copy(
            verifiedAt = null,
            lastRemoteKeyHex = newKeyHex ?: storedState.lastRemoteKeyHex
        )
    }

    /**
     * Explicitly accepts a new identity key without verification.
     */
    fun acceptNewKeyWithoutVerification(contactId: String, newKeyHex: String, safetyNumber: String): VerificationState {
        return VerificationState(
            contactId = contactId,
            safetyNumber = safetyNumber,
            verifiedAt = null,
            lastRemoteKeyHex = newKeyHex
        )
    }
}

