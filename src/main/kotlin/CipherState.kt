package nl.sanderdijkhuis.noise

data class CipherState(val cryptography: Cryptography, val key: CipherKey? = null, val nonce: Nonce = Nonce.zero) {

    fun encrypt(associatedData: Data, plaintext: Plaintext): State<CipherState, Ciphertext> =
        key?.let { k ->
            nonce.increment()?.let {
                State(copy(nonce = it), cryptography.encrypt(k, nonce, associatedData, plaintext))
            }
        } ?: State(this, plaintext.ciphertext)

    fun decrypt(data: Data, ciphertext: Ciphertext): State<CipherState, Plaintext>? =
        nonce.increment()?.let { n ->
            key?.let {
                cryptography.decrypt(it, nonce, data, ciphertext)?.let { p -> State(copy(nonce = n), p) }
            } ?: State(this, ciphertext.plaintext)
        }
}
