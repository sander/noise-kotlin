package nl.sanderdijkhuis.noise

import nl.sanderdijkhuis.noise.JavaCryptography.public
import org.junit.jupiter.api.Test

class JavaCryptographyTest {

    @Test
    fun testAgreement() {
        val pair1 = JavaCryptography.generateKeyPair()
        val pair2 = JavaCryptography.generateKeyPair()
        val secret1 = JavaCryptography.agree(pair1.private, pair2.public)
        val secret2 = JavaCryptography.agree(pair2.private, pair1.public)
        assert(!secret1.value.contentEquals(ByteArray(SharedSecret.SIZE) { 0x00 }))
        assert(secret1.value.contentEquals(secret2.value))
    }

    @Test
    fun testEncryption() {
        val key = CipherKey(ByteArray(CipherKey.SIZE) { 0x12 })
        val nonce = Nonce(ByteArray(Nonce.SIZE) { 0x34 })
        val plaintext = Plaintext("hello".encodeToByteArray())
        val associatedData = AssociatedData("world".encodeToByteArray())
        val ciphertext = JavaCryptography.encrypt(key, nonce, associatedData, plaintext)
        val decrypted = JavaCryptography.decrypt(key, nonce, associatedData, ciphertext)
        assert(plaintext.value.contentEquals(decrypted?.value))
    }

    @Test
    fun testCalculatePublicKey() {
        val pair = JavaCryptography.generateKeyPair()
        val calculated = pair.private.public()
        assert(calculated.value.contentEquals(pair.public.value))
    }
}