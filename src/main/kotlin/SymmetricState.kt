package nl.sanderdijkhuis.noise

data class SymmetricState(val cipherState: CipherState, val ck: ChainingKey, val h: Digest) {

    val cryptography get() = cipherState.cryptography

    fun mixKey(inputKeyMaterial: InputKeyMaterial) = let {
        val result = HashFunction.deriveKey2(cryptography, ck, inputKeyMaterial)
        copy(
            cipherState = CipherState(cryptography = cryptography, k = result.second.cipherKey()),
            ck = result.first.chainingKey()
        )
    }

    fun mixHash(data: Data) = copy(h = cryptography.hash(h.data() + data))

    fun encryptAndHash(plaintext: Plaintext) =
        cipherState.encryptWithAssociatedData(h.associatedData(), plaintext).let {
            State(mixHash(it.data()), it)
        }

    fun decryptAndHash(ciphertext: Ciphertext) =
        cipherState.decryptWithAssociatedData(h.associatedData(), ciphertext)

    fun split() = let {
        val zeroLen = InputKeyMaterial(ByteArray(0))
        val temporaryKeys = HashFunction.deriveKey2(cryptography, ck, zeroLen)
        val c1 = CipherState(cryptography, temporaryKeys.first.cipherKey())
        val c2 = CipherState(cryptography, temporaryKeys.second.cipherKey())
        Pair(c1, c2)
    }

    companion object {

        fun initialize(cryptography: Cryptography, protocolName: ProtocolName) = let {
            val h = if (protocolName.value.size <= HashConfiguration.hashSize.value)
                Digest(ByteArray(HashConfiguration.hashSize.value) { protocolName.value.getOrElse(it) { 0x00 } })
            else
                cryptography.hash(protocolName.data())
            val ck = ChainingKey(h)
            val state = CipherState(cryptography)
            SymmetricState(state, ck, h)
        }
    }
}
