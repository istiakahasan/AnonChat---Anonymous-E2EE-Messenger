package org.anonchat.crypto

import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.generators.HKDFBytesGenerator
import org.bouncycastle.crypto.generators.X25519KeyPairGenerator
import org.bouncycastle.crypto.params.*
import org.bouncycastle.crypto.signers.Ed25519Signer
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.security.SecureRandom
import java.util.Base64

/**
 * Task 2: X3DH Key Agreement (Android / Kotlin)
 *
 * Security Requirements Checklist Implemented:
 * - [x] Mutual authentication: Alice verifies Bob's signature on his Signed PreKey.
 * - [x] Forward secrecy: Ephemeral key + One-Time PreKey.
 * - [x] Keys are never logged to console.
 */
object X3DHProtocol {
    private val secureRandom = SecureRandom()
    private val base64Decoder = Base64.getDecoder()
    private val base64Encoder = Base64.getEncoder()
    private val PROTOCOL_INFO = "AnonChat_X3DH_v1_Protocol".toByteArray(Charsets.UTF_8)

    data class X3DHInitiation(
        val aliceIdentityKey: String,
        val aliceIdentityDhKey: String,
        val aliceEphemeralKey: String,
        val signedPreKeyId: Int,
        val oneTimePreKeyId: Int?
    ) {
        fun toJson(): JSONObject {
            return JSONObject().apply {
                put("alice_identity_key", aliceIdentityKey)
                put("alice_identity_dh_key", aliceIdentityDhKey)
                put("alice_ephemeral_key", aliceEphemeralKey)
                put("signed_prekey_id", signedPreKeyId)
                if (oneTimePreKeyId != null) put("one_time_prekey_id", oneTimePreKeyId)
            }
        }
    }

    /**
     * Alice initiates X3DH with Bob's PreKeyBundle.
     *
     * 1. Alice verifies Bob's signature on Signed PreKey using Bob's Identity Key.
     * 2. Alice generates ephemeral keypair EK_A.
     * 3. Alice computes DH1, DH2, DH3, DH4.
     * 4. Alice derives SharedSecret via HKDF-SHA256.
     */
    fun aliceInitiate(
        aliceManager: IdentityKeyManager,
        bobBundleJson: JSONObject
    ): Pair<ByteArray, X3DHInitiation> {
        // 1. Decode Bob's keys
        val bobIkBytes = base64Decoder.decode(bobBundleJson.getString("identity_key"))
        val bobIdentityKey = Ed25519PublicKeyParameters(bobIkBytes, 0)

        val bobIkDhBytes = base64Decoder.decode(bobBundleJson.getString("identity_dh_key"))
        val bobIdentityDhKey = X25519PublicKeyParameters(bobIkDhBytes, 0)

        val bobSpkBytes = base64Decoder.decode(bobBundleJson.getString("signed_prekey"))
        val bobSignedPreKey = X25519PublicKeyParameters(bobSpkBytes, 0)

        val signatureBytes = base64Decoder.decode(bobBundleJson.getString("signed_prekey_signature"))

        // 2. Verify signature on Bob's Signed PreKey
        val verifier = Ed25519Signer()
        verifier.init(false, bobIdentityKey)
        verifier.update(bobSpkBytes, 0, bobSpkBytes.size)
        if (!verifier.verifySignature(signatureBytes)) {
            throw SecurityException("Invalid signature on Bob's Signed PreKey!")
        }

        // 3. Generate Alice's Ephemeral Keypair (EK_A)
        val xGen = X25519KeyPairGenerator()
        xGen.init(X25519KeyGenerationParameters(secureRandom))
        val ekPair = xGen.generateKeyPair()
        val aliceEkPrivate = ekPair.private as X25519PrivateKeyParameters
        val aliceEkPublic = ekPair.public as X25519PublicKeyParameters

        // 4. Perform Diffie-Hellman:
        // DH1 = X25519(IK_A_dh_priv, SPK_B_pub)
        val dh1 = ByteArray(32)
        aliceManager.identityDhPrivateKey.generateSecret(bobSignedPreKey, dh1, 0)

        // DH2 = X25519(EK_A_priv, IK_B_dh_pub)
        val dh2 = ByteArray(32)
        aliceEkPrivate.generateSecret(bobIdentityDhKey, dh2, 0)

        // DH3 = X25519(EK_A_priv, SPK_B_pub)
        val dh3 = ByteArray(32)
        aliceEkPrivate.generateSecret(bobSignedPreKey, dh3, 0)

        // DH4 = X25519(EK_A_priv, OPK_B_pub) [if present]
        val opkArray = bobBundleJson.optJSONArray("one_time_prekeys")
        val (dh4, usedOpkId) = if (opkArray != null && opkArray.length() > 0) {
            val opkObj = opkArray.getJSONObject(0)
            val opkId = opkObj.getInt("id")
            val opkBytes = base64Decoder.decode(opkObj.getString("key"))
            val bobOpkPublic = X25519PublicKeyParameters(opkBytes, 0)
            val d4 = ByteArray(32)
            aliceEkPrivate.generateSecret(bobOpkPublic, d4, 0)
            Pair(d4, opkId)
        } else {
            Pair(null, null)
        }

        // 5. Concatenate key material: DH1 || DH2 || DH3 [|| DH4]
        val kmStream = ByteArrayOutputStream()
        kmStream.write(dh1)
        kmStream.write(dh2)
        kmStream.write(dh3)
        dh4?.let { kmStream.write(it) }
        val km = kmStream.toByteArray()

        // 6. HKDF-SHA256 to derive SharedSecret
        val sharedSecret = ByteArray(32)
        val hkdf = HKDFBytesGenerator(SHA256Digest())
        hkdf.init(HKDFParameters(km, ByteArray(32), PROTOCOL_INFO))
        hkdf.generateBytes(sharedSecret, 0, 32)

        val initiation = X3DHInitiation(
            aliceIdentityKey = base64Encoder.encodeToString(aliceManager.identityPublicKey.encoded),
            aliceIdentityDhKey = base64Encoder.encodeToString(aliceManager.identityDhPublicKey.encoded),
            aliceEphemeralKey = base64Encoder.encodeToString(aliceEkPublic.encoded),
            signedPreKeyId = bobBundleJson.getInt("signed_prekey_id"),
            oneTimePreKeyId = usedOpkId
        )

        return Pair(sharedSecret, initiation)
    }

    /**
     * Bob responds to X3DH initiation:
     * Derives identical SharedSecret using his private keys and destroys consumed OPK.
     */
    fun bobRespond(
        bobManager: IdentityKeyManager,
        initiation: X3DHInitiation
    ): ByteArray {
        val aliceIkDhBytes = base64Decoder.decode(initiation.aliceIdentityDhKey)
        val aliceIkDhPublic = X25519PublicKeyParameters(aliceIkDhBytes, 0)

        val aliceEkBytes = base64Decoder.decode(initiation.aliceEphemeralKey)
        val aliceEkPublic = X25519PublicKeyParameters(aliceEkBytes, 0)

        // DH1 = X25519(SPK_B_priv, IK_A_dh_pub)
        val dh1 = ByteArray(32)
        bobManager.signedPreKeyPrivate.generateSecret(aliceIkDhPublic, dh1, 0)

        // DH2 = X25519(IK_B_dh_priv, EK_A_pub)
        val dh2 = ByteArray(32)
        bobManager.identityDhPrivateKey.generateSecret(aliceEkPublic, dh2, 0)

        // DH3 = X25519(SPK_B_priv, EK_A_pub)
        val dh3 = ByteArray(32)
        bobManager.signedPreKeyPrivate.generateSecret(aliceEkPublic, dh3, 0)

        // DH4 = X25519(OPK_B_priv, EK_A_pub)
        val dh4 = if (initiation.oneTimePreKeyId != null) {
            val opkIndex = bobManager.oneTimePreKeys.indexOfFirst { it.first == initiation.oneTimePreKeyId }
            if (opkIndex == -1) throw NoSuchElementException("OPK ${initiation.oneTimePreKeyId} already consumed!")
            val (_, opkPriv, _) = bobManager.oneTimePreKeys.removeAt(opkIndex)
            val d4 = ByteArray(32)
            opkPriv.generateSecret(aliceEkPublic, d4, 0)
            d4
        } else {
            null
        }

        val kmStream = ByteArrayOutputStream()
        kmStream.write(dh1)
        kmStream.write(dh2)
        kmStream.write(dh3)
        dh4?.let { kmStream.write(it) }
        val km = kmStream.toByteArray()

        val sharedSecret = ByteArray(32)
        val hkdf = HKDFBytesGenerator(SHA256Digest())
        hkdf.init(HKDFParameters(km, ByteArray(32), PROTOCOL_INFO))
        hkdf.generateBytes(sharedSecret, 0, 32)

        return sharedSecret
    }
}

