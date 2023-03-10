package nl.sanderdijkhuis.noise

import nl.sanderdijkhuis.noise.cryptography.*
import nl.sanderdijkhuis.noise.data.State

data class Cipher(val cryptography: Cryptography, val key: CipherKey? = null, val nonce: Nonce = Nonce.zero) {

    fun encrypt(associatedData: AssociatedData, plaintext: Plaintext): State<Cipher, Ciphertext> =
        key?.let { k ->
            nonce.increment()?.let {
                State(copy(nonce = it), cryptography.encrypt(k, nonce, associatedData, plaintext))
            }
        } ?: State(this, Ciphertext(plaintext.data))

    fun decrypt(associatedData: AssociatedData, ciphertext: Ciphertext): State<Cipher, Plaintext>? =
        nonce.increment()?.let { n ->
            key?.let {
                cryptography.decrypt(it, nonce, associatedData, ciphertext)?.let { p -> State(copy(nonce = n), p) }
            } ?: State(this, ciphertext.plaintext)
        }
}