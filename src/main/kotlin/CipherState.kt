package nl.sanderdijkhuis.noise

data class CipherState(val cryptography: Cryptography, val k: CipherKey? = null, val n: Nonce = Nonce.zero()) {

    fun encryptWithAssociatedData(associatedData: AssociatedData, plaintext: Plaintext) =
        k?.let {
            println("Encrypting $k $n $associatedData $plaintext")
            cryptography.encrypt(it, n, associatedData, plaintext)
        } ?: plaintext.ciphertext

    fun decryptWithAssociatedData(associatedData: AssociatedData, ciphertext: Ciphertext) =
        k?.let {
            println("Decrypting $k $n $associatedData $ciphertext")
            cryptography.decrypt(it, n, associatedData, ciphertext)
        } ?: ciphertext.plaintext

//    fun rekey() = k?.rekey()
}
