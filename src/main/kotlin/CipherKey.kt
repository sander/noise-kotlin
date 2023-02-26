package nl.sanderdijkhuis.noise

@JvmInline
value class CipherKey(private val value: ByteArray) {

    init {
        require(value.size == SIZE)
    }

//    fun encrypt(
//        nonce: Nonce, associatedData: AssociatedData,
//        plaintext: Plaintext
//    ) = CipherFunction.Encrypt(this, nonce, associatedData, plaintext)
//
//    fun decrypt(
//        nonce: Nonce, associatedData: AssociatedData, ciphertext: Ciphertext
//    ) = CipherFunction.Decrypt(this, nonce, associatedData, ciphertext)
//
//    fun rekey() = CipherFunction.Rekey(this)

    companion object {

        const val SIZE = 32
    }
}