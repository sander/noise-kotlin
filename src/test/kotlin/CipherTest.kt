package nl.sanderdijkhuis.noise

import nl.sanderdijkhuis.noise.cryptography.AssociatedData
import nl.sanderdijkhuis.noise.cryptography.CipherKey
import nl.sanderdijkhuis.noise.cryptography.Nonce
import nl.sanderdijkhuis.noise.cryptography.Plaintext
import nl.sanderdijkhuis.noise.data.Data
import org.junit.jupiter.api.assertThrows
import kotlin.test.Test

@OptIn(ExperimentalStdlibApi::class)
class CipherTest {
    private val data = AssociatedData(Data.empty)
    private val plaintext = Plaintext(Data.empty)

    @Test
    fun `throws upon reaching nonce maximum while encrypting`() {
        val nonceTooHighToToUse = Nonce(ULong.MAX_VALUE - 1uL) // 2^64-2

        assertThrows<IllegalStateException> { cipher(nonceTooHighToToUse).encrypt(data, plaintext) }
    }

    @Test
    fun `throws upon reaching nonce maximum while decrypting`() {
        val nonceTooHighToEncrypt = Nonce(ULong.MAX_VALUE - 2uL) // 2^64-3
        val (cipher, ciphertext) = cipher(nonceTooHighToEncrypt).encrypt(data, plaintext)

        assertThrows<IllegalStateException> { cipher.decrypt(data, ciphertext) }
    }

    private fun cipher(nonce: Nonce) =
        Cipher(
            JavaCryptography,
            CipherKey(Data("76fef1ab184aa7539e3b62a43019ecafc621248b3ac2f5297dd5814e3bd560d3".hexToByteArray())),
            nonce
        )
}
