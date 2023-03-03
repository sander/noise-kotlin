package nl.sanderdijkhuis.noise

data class CipherState(val cryptography: Cryptography, val key: CipherKey? = null, val nonce: Nonce = Nonce.zero) {

    fun encryptWithAssociatedData(associatedData: AssociatedData, plaintext: Plaintext) =
        key?.let {
            println("Encrypting $key $nonce $associatedData $plaintext")
            State(copy(nonce = nonce.increment()), cryptography.encrypt(it, nonce, associatedData, plaintext))
        } ?: let {
            println("Returning plaintext $plaintext $nonce")
            State(this, plaintext.ciphertext)
        }

    fun decryptWithAssociatedData(data: AssociatedData, ciphertext: Ciphertext): State<CipherState, Plaintext>? = let {
        println("Decrypting $key $nonce $data $ciphertext")
        if (key == null)
            State(this, ciphertext.plaintext)
        else
            cryptography.decrypt(key, nonce, data, ciphertext)?.let {
                State(copy(nonce = nonce.increment()), it)
            }
    }
}
