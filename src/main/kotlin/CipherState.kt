package nl.sanderdijkhuis.noise

data class CipherState(val cryptography: Cryptography, val key: CipherKey? = null, val nonce: Nonce = Nonce.zero) {

    fun encryptWithAssociatedData(associatedData: Data, plaintext: Plaintext) =
        if (key == null)
            State(this, plaintext.ciphertext)
        else
            nonce.increment()?.let {
                State(copy(nonce = it), cryptography.encrypt(key, nonce, associatedData, plaintext))
            } ?: State(this, plaintext.ciphertext)

    fun decryptWithAssociatedData(data: Data, ciphertext: Ciphertext): State<CipherState, Plaintext>? =
        if (key == null)
            State(this, ciphertext.plaintext)
        else
            nonce.increment()?.let { n ->
                cryptography.decrypt(key, nonce, data, ciphertext)?.let { p ->
                    State(copy(nonce = n), p)
                }
            }
}
