package org.anonchat.crypto

import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.generators.HKDFBytesGenerator
import org.bouncycastle.crypto.generators.X25519KeyPairGenerator
import org.bouncycastle.crypto.macs.HMac
import org.bouncycastle.crypto.params.*
import org.json.JSONObject
import java.nio.ByteBuffer
import java.security.SecureRandom
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Task 3: Double Ratchet State Machine (Android / Kotlin)
 *
 * Security Requirements Checklist Implemented:
 * - [x] No plaintext is ever written to disk without encryption.
 * - [x] Keys are never logged to console.
 * - [x] Messages are padded to 4KB (4096 bytes) before encryption.
 * - [x] Header authenticated as AAD in AES-256-GCM.
 */
class DoubleRatchetSession private constructor(
    private var dhsPrivate: X25519PrivateKeyParameters,
    private var dhsPublic: X25519PublicKeyParameters,
    private var dhrPublic: X25519PublicKeyParameters?,
    private var rootKey: ByteArray,
    private var sendingChainKey: ByteArray?,
    private var receivingChainKey: ByteArray?,
    private var ns: Int = 0,
    private var nr: Int = 0,
    private var pn: Int = 0,
    var bobFirstMessage: Boolean = false
) {
    private val secureRandom = SecureRandom()
    private val base64Encoder = Base64.getEncoder()
    private val base64Decoder = Base64.getDecoder()
    private val skippedMessageKeys = mutableMapOf<Pair<String, Int>, ByteArray>()

    companion object {
        const val FIXED_BLOCK_SIZE = 4096

        /**
         * Initializes Sender State (Alice, who initiated X3DH).
         *
         * Inputs:
         * - sharedSecret: 32-byte output from X3DH
         * - bobRatchetPublic: Bob's signed prekey public key (DH ratchet key published by Bob)
         *
         * Initialize:
         * - DHs = fresh X25519 keypair
         * - DHr = bobRatchetPublic
         * - RK, CKs = KDF_RK(sharedSecret, DH(DHs_private, DHr))
         * - CKr = null
         * - Ns = 0, Nr = 0, PNs = 0, MKSKIPPED = empty map
         * - BOB_FIRST_MESSAGE = false
         */
        fun initSenderState(
            sharedSecret: ByteArray,
            bobRatchetPublic: X25519PublicKeyParameters
        ): DoubleRatchetSession {
            val secureRandom = SecureRandom()
            val xGen = X25519KeyPairGenerator()
            xGen.init(X25519KeyGenerationParameters(secureRandom))
            val pair = xGen.generateKeyPair()
            val dhsPriv = pair.private as X25519PrivateKeyParameters
            val dhsPub = pair.public as X25519PublicKeyParameters

            val dhOut = ByteArray(32)
            dhsPriv.generateSecret(bobRatchetPublic, dhOut, 0)

            val (newRk, cks) = kdfRk(sharedSecret, dhOut)

            return DoubleRatchetSession(
                dhsPrivate = dhsPriv,
                dhsPublic = dhsPub,
                dhrPublic = bobRatchetPublic,
                rootKey = newRk,
                sendingChainKey = cks,
                receivingChainKey = null,
                ns = 0,
                nr = 0,
                pn = 0,
                bobFirstMessage = false
            )
        }

        /**
         * Initializes Alice's ratchet session after X3DH (alias for initSenderState).
         */
        fun initAlice(
            sharedSecret: ByteArray,
            bobSpkPublic: X25519PublicKeyParameters
        ): DoubleRatchetSession = initSenderState(sharedSecret, bobSpkPublic)

        /**
         * Initializes Receiver State (Bob).
         *
         * Inputs:
         * - sharedSecret: same 32 bytes from X3DH
         * - bobRatchetPrivate, bobRatchetPublic: Bob's signed prekey keypair
         *
         * Initialize:
         * - DHs = bobRatchetKeypair
         * - DHr = null
         * - RK = sharedSecret
         * - CKs = null, CKr = null
         * - Ns = 0, Nr = 0, PNs = 0, MKSKIPPED = empty map
         * - BOB_FIRST_MESSAGE = true
         */
        fun initReceiverState(
            sharedSecret: ByteArray,
            bobRatchetPrivate: X25519PrivateKeyParameters,
            bobRatchetPublic: X25519PublicKeyParameters
        ): DoubleRatchetSession {
            return DoubleRatchetSession(
                dhsPrivate = bobRatchetPrivate,
                dhsPublic = bobRatchetPublic,
                dhrPublic = null,
                rootKey = sharedSecret.clone(),
                sendingChainKey = null,
                receivingChainKey = null,
                ns = 0,
                nr = 0,
                pn = 0,
                bobFirstMessage = true
            )
        }

        /**
         * Initializes Bob's ratchet session after X3DH (alias for initReceiverState).
         */
        fun initBob(
            sharedSecret: ByteArray,
            bobSpkPrivate: X25519PrivateKeyParameters,
            bobSpkPublic: X25519PublicKeyParameters
        ): DoubleRatchetSession = initReceiverState(sharedSecret, bobSpkPrivate, bobSpkPublic)

        private fun kdfRk(rk: ByteArray, dhOut: ByteArray): Pair<ByteArray, ByteArray> {
            val hkdf = HKDFBytesGenerator(SHA256Digest())
            // Sub-Step SM.4: Standard Signal Double Ratchet KDF info string ("DoubleRatchet")
            hkdf.init(HKDFParameters(dhOut, rk, "DoubleRatchet".toByteArray(Charsets.UTF_8)))
            val okm = ByteArray(64)
            hkdf.generateBytes(okm, 0, 64)
            val newRk = okm.copyOfRange(0, 32)
            val nextCk = okm.copyOfRange(32, 64)
            return Pair(newRk, nextCk)
        }

        private fun kdfCk(ck: ByteArray): Pair<ByteArray, ByteArray> {
            val hmac1 = HMac(SHA256Digest())
            hmac1.init(KeyParameter(ck))
            hmac1.update(byteArrayOf(0x01), 0, 1)
            val mk = ByteArray(32)
            hmac1.doFinal(mk, 0)

            val hmac2 = HMac(SHA256Digest())
            hmac2.init(KeyParameter(ck))
            hmac2.update(byteArrayOf(0x02), 0, 1)
            val nextCk = ByteArray(32)
            hmac2.doFinal(nextCk, 0)

            return Pair(nextCk, mk)
        }
    }

    data class Header(
        val dhPub: String,
        val pn: Int,
        val n: Int
    ) {
        fun toJsonBytes(): ByteArray {
            val obj = JSONObject()
            // Sub-Step SM.4: Canonical Signal Double Ratchet header format (dh, pn, n)
            obj.put("dh", dhPub)
            obj.put("pn", pn)
            obj.put("n", n)
            return obj.toString().toByteArray(Charsets.UTF_8)
        }

        companion object {
            fun fromJson(json: JSONObject): Header {
                val dh = if (json.has("dh")) json.getString("dh") else json.getString("dh_pub")
                return Header(
                    dhPub = dh,
                    pn = json.getInt("pn"),
                    n = json.getInt("n")
                )
            }
        }
    }

    data class EncryptedEnvelope(
        val header: Header,
        val ciphertext: String,
        val nonce: String
    ) {
        fun toJson(): JSONObject {
            return JSONObject().apply {
                put("v", 1)
                put("header", JSONObject().apply {
                    put("dh", header.dhPub)
                    put("pn", header.pn)
                    put("n", header.n)
                })
                put("ciphertext", ciphertext)
                put("nonce", nonce)
            }
        }
    }

    /**
     * Encrypts plaintext message:
     * - Advances sending chain
     * - Pads message to 4KB (4096 bytes)
     * - Authenticates header as AAD in AES-256-GCM
     */
    fun ratchetEncrypt(plaintext: ByteArray): EncryptedEnvelope {
        val currentCks = sendingChainKey ?: throw IllegalStateException("No sending chain key")
        val (nextCks, mk) = kdfCk(currentCks)
        sendingChainKey = nextCks

        val header = Header(
            dhPub = base64Encoder.encodeToString(dhsPublic.encoded),
            pn = pn,
            n = ns
        )
        ns += 1

        val paddedPlaintext = padTo4KB(plaintext)

        // Sub-Step SM.4: CSPRNG 96-bit (12-byte) random nonce generation (no custom counter nonce)
        val nonce = ByteArray(12)
        secureRandom.nextBytes(nonce)

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val keySpec = SecretKeySpec(mk, "AES")
        val gcmSpec = GCMParameterSpec(128, nonce)
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec)
        cipher.updateAAD(header.toJsonBytes())

        val ciphertext = cipher.doFinal(paddedPlaintext)

        return EncryptedEnvelope(
            header = header,
            ciphertext = base64Encoder.encodeToString(ciphertext),
            nonce = base64Encoder.encodeToString(nonce)
        )
    }

    /**
     * Decrypts incoming message:
     * - Advances DH ratchet if new peer DH key received
     * - Verifies header AAD
     * - Decrypts with AES-256-GCM
     * - Strips 4KB padding
     */
    fun ratchetDecrypt(envelope: EncryptedEnvelope): ByteArray {
        val peerDhBytes = base64Decoder.decode(envelope.header.dhPub)
        val peerDhPublic = X25519PublicKeyParameters(peerDhBytes, 0)

        val isNewDh = dhrPublic == null || !dhrPublic!!.encoded.contentEquals(peerDhPublic.encoded)
        if (isNewDh) {
            skipMessageKeys(envelope.header.pn)
            dhRatchet(peerDhPublic)
            bobFirstMessage = false
        } else if (envelope.header.n < nr) {
            // Sub-Step SM.2: Enforce message key uniqueness
            throw IllegalStateException("Duplicate or already-consumed message: message key cannot be reused")
        }

        skipMessageKeys(envelope.header.n)

        val currentCkr = receivingChainKey ?: throw IllegalStateException("No receiving chain key")
        val (nextCkr, mk) = kdfCk(currentCkr)
        receivingChainKey = nextCkr
        nr += 1
        bobFirstMessage = false

        val ciphertext = base64Decoder.decode(envelope.ciphertext)
        val nonce = base64Decoder.decode(envelope.nonce)

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val keySpec = SecretKeySpec(mk, "AES")
        val gcmSpec = GCMParameterSpec(128, nonce)
        cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec)
        cipher.updateAAD(envelope.header.toJsonBytes())

        val paddedPlaintext = cipher.doFinal(ciphertext)
        return unpadFrom4KB(paddedPlaintext)
    }

    private fun dhRatchet(peerDhPublic: X25519PublicKeyParameters) {
        pn = ns
        ns = 0
        nr = 0
        dhrPublic = peerDhPublic

        val dhOutRx = ByteArray(32)
        dhsPrivate.generateSecret(peerDhPublic, dhOutRx, 0)
        val (newRkRx, ckr) = kdfRk(rootKey, dhOutRx)
        rootKey = newRkRx
        receivingChainKey = ckr

        val xGen = X25519KeyPairGenerator()
        xGen.init(X25519KeyGenerationParameters(secureRandom))
        val pair = xGen.generateKeyPair()
        dhsPrivate = pair.private as X25519PrivateKeyParameters
        dhsPublic = pair.public as X25519PublicKeyParameters

        val dhOutTx = ByteArray(32)
        dhsPrivate.generateSecret(peerDhPublic, dhOutTx, 0)
        val (newRkTx, cks) = kdfRk(rootKey, dhOutTx)
        rootKey = newRkTx
        sendingChainKey = cks
    }

    private fun skipMessageKeys(until: Int) {
        val ckr = receivingChainKey ?: return
        var currentCkr = ckr
        val dhrBytes = dhrPublic?.encoded?.let { base64Encoder.encodeToString(it) } ?: return

        while (nr < until) {
            val (nextCkr, mk) = kdfCk(currentCkr)
            currentCkr = nextCkr
            skippedMessageKeys[Pair(dhrBytes, nr)] = mk
            nr += 1
        }
        receivingChainKey = currentCkr
    }

    /**
     * Pads payload to fixed 4096-byte blocks with cryptographic random bytes.
     */
    private fun padTo4KB(payload: ByteArray): ByteArray {
        val totalCapacity = ((payload.size + 4 + FIXED_BLOCK_SIZE - 1) / FIXED_BLOCK_SIZE) * FIXED_BLOCK_SIZE
        val buffer = ByteBuffer.allocate(totalCapacity)
        buffer.putInt(payload.size)
        buffer.put(payload)
        val padLen = totalCapacity - 4 - payload.size
        val randomPadding = ByteArray(padLen)
        secureRandom.nextBytes(randomPadding)
        buffer.put(randomPadding)
        return buffer.array()
    }

    private fun unpadFrom4KB(padded: ByteArray): ByteArray {
        val buffer = ByteBuffer.wrap(padded)
        val length = buffer.int
        val payload = ByteArray(length)
        buffer.get(payload)
        return payload
    }

    /**
     * Serializes active ratchet state to JSON for encrypted durable storage.
     */
    fun toJsonString(): String {
        val root = JSONObject()
        root.put("DHs_priv", base64Encoder.encodeToString(dhsPrivate.encoded))
        root.put("DHs_pub", base64Encoder.encodeToString(dhsPublic.encoded))
        root.put("DHr", dhrPublic?.let { base64Encoder.encodeToString(it.encoded) })
        root.put("RK", base64Encoder.encodeToString(rootKey))
        root.put("CKs", sendingChainKey?.let { base64Encoder.encodeToString(it) })
        root.put("CKr", receivingChainKey?.let { base64Encoder.encodeToString(it) })
        root.put("Ns", ns)
        root.put("Nr", nr)
        root.put("PNs", pn)
        root.put("bob_first_message", bobFirstMessage)
        val skippedObj = JSONObject()
        for ((k, v) in skippedMessageKeys) {
            skippedObj.put("${k.first}:${k.second}", base64Encoder.encodeToString(v))
        }
        root.put("MKSKIPPED", skippedObj)
        return root.toString()
    }

    /**
     * Sub-Step SM.3: Persist ratchet state durably before releasing ciphertext to network.
     *
     * Research on libsignal store implementations explicitly warns:
     * "The Double Ratchet has no per-message random nonce guard, so a write that is lost (crash, unflushed buffer)
     * or rolled back (restored backup, cloned image) makes the next send reuse a message key and IV it has
     * already used — which costs confidentiality, forward secrecy and replay protection" [citation:25].
     */
    fun durableRatchetEncrypt(
        plaintext: ByteArray,
        saveDurable: (sessionJson: String) -> Unit,
        sendOverNetwork: (envelope: EncryptedEnvelope) -> Unit
    ): EncryptedEnvelope {
        val envelope = ratchetEncrypt(plaintext)
        val serialized = toJsonString()
        saveDurable(serialized)
        sendOverNetwork(envelope)
        return envelope
    }

    /**
     * Sub-Step SM.3: Persist ratchet state durably before acting on / delivering decrypted plaintext.
     */
    fun durableRatchetDecrypt(
        envelope: EncryptedEnvelope,
        saveDurable: (sessionJson: String) -> Unit,
        deliverOrDisplay: (plaintext: ByteArray) -> Unit
    ): ByteArray {
        val plaintext = ratchetDecrypt(envelope)
        val serialized = toJsonString()
        saveDurable(serialized)
        deliverOrDisplay(plaintext)
        return plaintext
    }
}

