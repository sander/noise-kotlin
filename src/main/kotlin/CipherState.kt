package nl.sanderdijkhuis.noise

data class CipherState(val cryptography: Cryptography, val k: CipherKey? = null, val n: Nonce = Nonce.zero()) {

    fun encryptWithAssociatedData(associatedData: AssociatedData, plaintext: Plaintext) =
        k?.let { cryptography.encrypt(it, n, associatedData, plaintext) }

    fun decryptWithAssociatedData(associatedData: AssociatedData, ciphertext: Ciphertext) =
        k?.let { cryptography.decrypt(it, n, associatedData, ciphertext) }

//    fun rekey() = k?.rekey()
}
