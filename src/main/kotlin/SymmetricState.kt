package nl.sanderdijkhuis.noise

data class SymmetricState(val cipherState: CipherState, val key: ChainingKey, val digest: Digest) {

    val cryptography get() = cipherState.cryptography

    fun mixKey(inputKeyMaterial: InputKeyMaterial) = let {
        val result = HashFunction.deriveKeys(cryptography, key, inputKeyMaterial)
        copy(
            cipherState = CipherState(cryptography = cryptography, key = result.second.cipherKey),
            key = result.first.chainingKey
        )
    }

    fun mixHash(data: Data) = let {
        val result = copy(digest = cryptography.hash(digest.data + data))
        println("Mixing $digest + $data = ${result.digest}")
        result
    }

    fun encryptAndHash(plaintext: Plaintext) = let {
        println("Encrypting and hashing $digest $plaintext")
        cipherState.encryptWithAssociatedData(digest.associatedData, plaintext).let {
            State(copy(cipherState = it.current).mixHash(it.result.data), it.result)
        }
    }

    fun decryptAndHash(ciphertext: Ciphertext) = let {
        println("Decrypting and hashing $digest $ciphertext")
        cipherState.decryptWithAssociatedData(digest.associatedData, ciphertext)?.let {
            State(copy(cipherState = it.current).mixHash(ciphertext.data), it.result)
        }
    }

    fun split() = let {
        val zeroLen = InputKeyMaterial(ByteArray(0))
        val temporaryKeys = HashFunction.deriveKeys(cryptography, key, zeroLen)
        val c1 = CipherState(cryptography, temporaryKeys.first.cipherKey)
        val c2 = CipherState(cryptography, temporaryKeys.second.cipherKey)
        Pair(c1, c2)
    }

    companion object {

        fun initialize(cryptography: Cryptography, protocolName: ProtocolName) = let {
            println("Initializing $cryptography $protocolName ${protocolName.size} ${HashFunction.HASH_SIZE}")
            val h = if (protocolName.size <= HashFunction.HASH_SIZE)
                Digest(Data(HashFunction.HASH_SIZE.byteArray { protocolName.value.getOrElse(it) { 0x00 } }))
            else
                cryptography.hash(protocolName.data)
            val ck = ChainingKey(h)
            val state = CipherState(cryptography)
            SymmetricState(state, ck, h)
        }
    }
}
