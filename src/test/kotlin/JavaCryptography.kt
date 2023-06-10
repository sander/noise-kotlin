package nl.sanderdijkhuis.noise

import nl.sanderdijkhuis.noise.cryptography.*
import nl.sanderdijkhuis.noise.data.Data
import org.bouncycastle.crypto.InvalidCipherTextException
import org.bouncycastle.crypto.modes.ChaCha20Poly1305
import org.bouncycastle.crypto.params.AEADParameters
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.math.ec.rfc7748.X25519
import java.security.MessageDigest
import java.security.SecureRandom

object JavaCryptography : Cryptography {
    fun PrivateKey.public() =
        PublicKey(Data(ByteArray(X25519.POINT_SIZE).apply { X25519.generatePublicKey(value, 0, this, 0) }))

    fun generateKeyPair() = let {
        val seed = ByteArray(X25519.SCALAR_SIZE).apply { X25519.generatePrivateKey(SecureRandom(), this) }
        val privateKey = PrivateKey(seed)
        Pair(privateKey.public(), privateKey)
    }

    override fun agree(privateKey: PrivateKey, publicKey: PublicKey) = SharedSecret(
        Data(ByteArray(X25519.POINT_SIZE).apply {
            X25519.calculateAgreement(privateKey.value, 0, publicKey.data.value, 0, this, 0)
        })
    )

    override fun encrypt(
        key: CipherKey,
        nonce: Nonce,
        associatedData: AssociatedData,
        plaintext: Plaintext
    ) = with(ChaCha20Poly1305()) {
        init(true, parameters(key, nonce, associatedData))
        ByteArray(plaintext.data.value.size + AUTHENTICATION_TAG_BYTE_SIZE).let {
            doFinal(it, processBytes(plaintext.data.value, 0, plaintext.data.value.size, it, 0))
            Ciphertext(Data(it))
        }
    }

    override fun decrypt(
        key: CipherKey,
        nonce: Nonce,
        associatedData: AssociatedData,
        ciphertext: Ciphertext
    ) = with(ChaCha20Poly1305()) {
        init(false, parameters(key, nonce, associatedData))
        ByteArray(ciphertext.data.value.size - AUTHENTICATION_TAG_BYTE_SIZE).let {
            try {
                doFinal(it, processBytes(ciphertext.data.value, 0, ciphertext.data.value.size, it, 0))
                Plaintext(Data(it))
            } catch (e: InvalidCipherTextException) {
                null
            }
        }
    }

    override fun hash(data: Data) = Digest(
        Data(MessageDigest.getInstance("SHA-256").digest(data.value))
    )

    private const val AUTHENTICATION_TAG_BYTE_SIZE = 16

    private fun parameters(key: CipherKey, nonce: Nonce, associatedData: AssociatedData) = AEADParameters(
        KeyParameter(key.data.value),
        AUTHENTICATION_TAG_BYTE_SIZE * Byte.SIZE_BITS,
        ByteArray(4) { 0x00 } + nonce.bytes,
        associatedData.data.value
    )
}
