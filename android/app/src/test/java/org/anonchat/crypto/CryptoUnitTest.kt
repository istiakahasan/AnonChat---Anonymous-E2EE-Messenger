package org.anonchat.crypto

import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator
import org.bouncycastle.crypto.generators.X25519KeyPairGenerator
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.params.X25519KeyGenerationParameters
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.bouncycastle.crypto.params.X25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import org.junit.Assert.*
import org.junit.Test
import java.nio.ByteBuffer
import java.security.SecureRandom

class CryptoUnitTest {
    private val secureRandom = SecureRandom()

    @Test
    fun testEd25519SigningAndVerification() {
        val edGen = Ed25519KeyPairGenerator()
        edGen.init(Ed25519KeyGenerationParameters(secureRandom))
        val pair = edGen.generateKeyPair()
        val priv = pair.private as Ed25519PrivateKeyParameters
        val pub = pair.public as Ed25519PublicKeyParameters

        val message = "AnonChat Signed PreKey Signature Test".toByteArray(Charsets.UTF_8)

        // Sign
        val signer = Ed25519Signer()
        signer.init(true, priv)
        signer.update(message, 0, message.size)
        val signature = signer.generateSignature()

        // Verify
        val verifier = Ed25519Signer()
        verifier.init(false, pub)
        verifier.update(message, 0, message.size)
        val isValid = verifier.verifySignature(signature)

        assertTrue("Ed25519 signature must verify successfully", isValid)
    }

    @Test
    fun testX25519DiffieHellmanSymmetry() {
        val xGen = X25519KeyPairGenerator()
        xGen.init(X25519KeyGenerationParameters(secureRandom))

        val alicePair = xGen.generateKeyPair()
        val alicePriv = alicePair.private as X25519PrivateKeyParameters
        val alicePub = alicePair.public as X25519PublicKeyParameters

        val bobPair = xGen.generateKeyPair()
        val bobPriv = bobPair.private as X25519PrivateKeyParameters
        val bobPub = bobPair.public as X25519PublicKeyParameters

        // Alice computes DH(Alice_priv, Bob_pub)
        val aliceShared = ByteArray(32)
        alicePriv.generateSecret(bobPub, aliceShared, 0)

        // Bob computes DH(Bob_priv, Alice_pub)
        val bobShared = ByteArray(32)
        bobPriv.generateSecret(alicePub, bobShared, 0)

        assertArrayEquals("X25519 DH outputs must be identical", aliceShared, bobShared)
    }

    @Test
    fun testFixed4KBPaddingCalculation() {
        val blockSize = 4096
        val payload = "Hello world!".toByteArray(Charsets.UTF_8)
        val minCapacity = 4 + payload.size

        val targetSize = ((minCapacity + blockSize - 1) / blockSize) * blockSize
        assertEquals(4096, targetSize)

        val buffer = ByteBuffer.allocate(targetSize)
        buffer.putInt(payload.size)
        buffer.put(payload)
        val padLen = targetSize - 4 - payload.size
        buffer.put(ByteArray(padLen))

        assertEquals(4096, buffer.array().size)

        // Recover
        val readBuffer = ByteBuffer.wrap(buffer.array())
        val len = readBuffer.int
        val recovered = ByteArray(len)
        readBuffer.get(recovered)

        assertEquals("Hello world!", String(recovered, Charsets.UTF_8))
    }
}

