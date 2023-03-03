package nl.sanderdijkhuis.noise

data class SymmetricState(val cipherState: CipherState, val key: ChainingKey, val handshakeHash: HandshakeHash) {

    val cryptography get() = cipherState.cryptography

    fun mixKey(inputKeyMaterial: InputKeyMaterial) = let {
        val result = HashFunction.deriveKeys(cryptography, key, inputKeyMaterial)
        copy(
            cipherState = CipherState(cryptography = cryptography, key = result.second.cipherKey),
            key = result.first.chainingKey
        )
    }

    fun mixHash(data: Data) = let {
        val result = copy(handshakeHash = HandshakeHash(cryptography.hash(handshakeHash.digest.data + data)))
        println("Mixing $handshakeHash + $data = ${result.handshakeHash}")
        result
    }

    fun encryptAndHash(plaintext: Plaintext) = let {
        println("Encrypting and hashing $handshakeHash $plaintext")
        cipherState.encryptWithAssociatedData(handshakeHash.digest.data, plaintext).let {
            State(copy(cipherState = it.current).mixHash(it.result.data), it.result)
        }
    }

    fun decryptAndHash(ciphertext: Ciphertext) = let {
        println("Decrypting and hashing $handshakeHash $ciphertext")
        cipherState.decryptWithAssociatedData(handshakeHash.digest.data, ciphertext)?.let {
            State(copy(cipherState = it.current).mixHash(ciphertext.data), it.result)
        }
    }

    fun split() = let {
        val zeroLen = InputKeyMaterial(Data.empty)
        val temporaryKeys = HashFunction.deriveKeys(cryptography, key, zeroLen)
        val c1 = CipherState(cryptography, temporaryKeys.first.cipherKey)
        val c2 = CipherState(cryptography, temporaryKeys.second.cipherKey)
        Pair(c1, c2)
    }

    companion object {

        fun initialize(cryptography: Cryptography, protocolName: ProtocolName) = let {
            println("Initializing $cryptography $protocolName ${protocolName.data.size} ${HashFunction.HASH_SIZE}")
            val h = if (protocolName.data.size <= HashFunction.HASH_SIZE)
                Digest(Data(HashFunction.HASH_SIZE.byteArray { protocolName.data.value.getOrElse(it) { 0x00 } }))
            else
                cryptography.hash(protocolName.data)
            val ck = ChainingKey(h)
            val state = CipherState(cryptography)
            SymmetricState(state, ck, HandshakeHash(h))
        }
    }
}
