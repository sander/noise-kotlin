package nl.sanderdijkhuis.noise

data class CipherState(val cryptography: Cryptography, val k: CipherKey? = null, val n: Nonce = Nonce.zero()) {

    fun encryptWithAssociatedData(associatedData: AssociatedData, plaintext: Plaintext) =
        k?.let {
            println("Encrypting $k $n $associatedData $plaintext")
            State(copy(n = n.increment()), cryptography.encrypt(it, n, associatedData, plaintext))
        } ?: let {
            println("Returning plaintext $plaintext $n")
            State(this, plaintext.ciphertext)
        }

    fun decryptWithAssociatedData(
        associatedData: AssociatedData,
        ciphertext: Ciphertext
    ): State<CipherState, Plaintext>? = let {
        println("Decrypting $k $n $associatedData $ciphertext")
        if (k == null)
            State(this, ciphertext.plaintext)
        else
            cryptography.decrypt(k, n, associatedData, ciphertext)?.let {
                State(copy(n = n.increment()), it)
            }
    }

//    fun rekey() = k?.rekey()
}
