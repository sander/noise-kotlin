package nl.sanderdijkhuis.noise

import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.interfaces.XECPrivateKey
import java.security.spec.NamedParameterSpec
import java.security.spec.XECPrivateKeySpec
import java.security.spec.XECPublicKeySpec
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.experimental.and

object JavaCryptography : Cryptography {
    private val spec get() = NamedParameterSpec("X25519")
    private val agreementFactory get() = KeyFactory.getInstance("XDH")
    private val cipher get() = Cipher.getInstance("ChaCha20-Poly1305")

    private fun PublicKey.toJava() = let {
        val uArray = value.reversedArray()
        uArray[0] = uArray[0] and ((1 shl (255 % 8)) - 1).toByte()
        agreementFactory.generatePublic(XECPublicKeySpec(spec, BigInteger(1, uArray)))
    }

    private fun PrivateKey.toJava() =
        agreementFactory.generatePrivate(XECPrivateKeySpec(spec, value))

    /**  RFC 7748 § 6.1 */
    fun PrivateKey.public() = PublicKey(agree(this, PublicKey(byteArrayOf(0x09) + ByteArray(31) { 0x00 })).value)

    private fun CipherKey.toJava() = SecretKeySpec(value, "ChaCha20")

    private fun Nonce.toJava() = IvParameterSpec(ByteArray(4) { 0x00 } + value)

    fun generateKeyPair(): KeyPair {
        val generator = KeyPairGenerator.getInstance("XDH").apply { initialize(spec) }
        val pair = generator.generateKeyPair()
        return KeyPair(
            PublicKey(pair.public.encoded.sliceArray(IntRange(12, 43))),
            PrivateKey((pair.private as XECPrivateKey).scalar.get())
        )
    }

    override fun agree(privateKey: PrivateKey, publicKey: PublicKey) = SharedSecret(
        KeyAgreement.getInstance("X25519").apply {
            init(privateKey.toJava())
            doPhase(publicKey.toJava(), true)
        }.generateSecret()
    )

    override fun encrypt(
        key: CipherKey,
        nonce: Nonce,
        associatedData: AssociatedData,
        plaintext: Plaintext
    ) = Ciphertext(with(cipher) {
        init(Cipher.ENCRYPT_MODE, key.toJava(), nonce.toJava())
        updateAAD(associatedData.value)
        doFinal(plaintext.value)
    })

    override fun decrypt(
        key: CipherKey,
        nonce: Nonce,
        associatedData: AssociatedData,
        ciphertext: Ciphertext
    ) = with(cipher) {
        init(Cipher.DECRYPT_MODE, key.toJava(), nonce.toJava())
        updateAAD(associatedData.value)
        doFinal(ciphertext.value)
    }?.let { Plaintext(it) }

    override fun hash(data: Data) = Digest(
        MessageDigest.getInstance("SHA-256").digest(data.value)
    )
}