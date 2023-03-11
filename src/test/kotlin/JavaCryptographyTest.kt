package nl.sanderdijkhuis.noise

import nl.sanderdijkhuis.noise.JavaCryptography.public
import org.junit.jupiter.api.Test

class JavaCryptographyTest {

    @Test
    fun testAgreement() {
        val pair1 = JavaCryptography.generateKeyPair()
        val pair2 = JavaCryptography.generateKeyPair()
        val secret1 = JavaCryptography.agree(pair1.second, pair2.first)
        val secret2 = JavaCryptography.agree(pair2.second, pair1.first)
        assert(secret1.data != Data(SharedSecret.SIZE.byteArray { 0x00 }))
        assert(secret1.data == secret2.data)
    }

    @Test
    fun testEncryption() {
        val key = CipherKey(Data(CipherKey.SIZE.byteArray { 0x12 }))
        val nonce = Nonce.from(Nonce.SIZE.byteArray { 0x34 })!!
        val plaintext = Plaintext(Data("hello".encodeToByteArray()))
        val associatedData = Data("world".encodeToByteArray())
        val ciphertext = JavaCryptography.encrypt(key, nonce, associatedData, plaintext)
        val decrypted = JavaCryptography.decrypt(key, nonce, associatedData, ciphertext)
        assert(plaintext.data == decrypted?.data)
    }

    @Test
    fun testCalculatePublicKey() {
        val pair = JavaCryptography.generateKeyPair()
        val calculated = pair.second.public()
        assert(calculated.data == pair.first.data)
    }
}