package nl.sanderdijkhuis.noise

import nl.sanderdijkhuis.noise.cryptography.*
import nl.sanderdijkhuis.noise.data.State

/**
 * Encompasses all Noise protocol cipher state required to encrypt and decrypt data.
 *
 * Note that as per Noise revision 34 § 5.1, [[key]] may be uninitialized. In this case [[encrypt]] and [[decrypt]]
 * are identity functions over the plaintext and ciphertext.
 *
 * Encryption and decryption throw if incrementing [[nonce]] results in its maximum value: it means too many messages
 * have been exchanged. Too many is a lot indeed: 2^64-1.
 */
data class Cipher(val cryptography: Cryptography, val key: CipherKey? = null, val nonce: Nonce = Nonce.zero) {

    fun encrypt(associatedData: AssociatedData, plaintext: Plaintext): State<Cipher, Ciphertext> =
        key?.let { k ->
            nonce.increment().let { n ->
                checkNotNull(n) { "Too many messages" }
                State(copy(nonce = n), cryptography.encrypt(k, nonce, associatedData, plaintext))
            }
        } ?: State(this, Ciphertext(plaintext.data))

    fun decrypt(associatedData: AssociatedData, ciphertext: Ciphertext): State<Cipher, Plaintext>? =
        nonce.increment().let { n ->
            checkNotNull(n) { "Too many messages" }
            key?.let {
                cryptography.decrypt(it, nonce, associatedData, ciphertext)?.let { p -> State(copy(nonce = n), p) }
            } ?: State(this, ciphertext.plaintext)
        }
}
