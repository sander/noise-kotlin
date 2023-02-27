package nl.sanderdijkhuis.noise

data class CipherState(val cryptography: Cryptography, val k: CipherKey? = null, val n: Nonce = Nonce.zero()) {

    fun encryptWithAssociatedData(associatedData: AssociatedData, plaintext: Plaintext) =
        k?.let {
            println("Encrypting $k $n $associatedData $plaintext")
            cryptography.encrypt(it, n, associatedData, plaintext)
        } ?: plaintext.ciphertext

    fun decryptWithAssociatedData(associatedData: AssociatedData, ciphertext: Ciphertext) =
        if (k == null) ciphertext.plaintext else
        let {
            println("Decrypting $k $n $associatedData $ciphertext")
            cryptography.decrypt(k, n, associatedData, ciphertext)
        }

//    fun rekey() = k?.rekey()
}
