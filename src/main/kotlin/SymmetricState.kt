package nl.sanderdijkhuis.noise

data class SymmetricState(val cipherState: CipherState, val key: ChainingKey, val handshakeHash: HandshakeHash) {

    @JvmInline
    value class ChainingKey(val digest: Digest)

    @JvmInline
    value class HandshakeHash(val digest: Digest)

    val cryptography get() = cipherState.cryptography

    fun mixKey(inputKeyMaterial: InputKeyMaterial) = let {
        val result = deriveKeys(cryptography, key, inputKeyMaterial)
        copy(
            cipherState = CipherState(cryptography = cryptography, key = result.second.cipherKey),
            key = ChainingKey(result.first.digest)
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
        val temporaryKeys = deriveKeys(cryptography, key, zeroLen)
        val c1 = CipherState(cryptography, temporaryKeys.first.cipherKey)
        val c2 = CipherState(cryptography, temporaryKeys.second.cipherKey)
        Pair(c1, c2)
    }

    companion object {

        fun initialize(cryptography: Cryptography, protocolName: ProtocolName) = let {
            println("Initializing $cryptography $protocolName ${protocolName.data.size} ${Digest.SIZE}")
            val h = if (protocolName.data.size <= Digest.SIZE)
                Digest(Data(Digest.SIZE.byteArray { protocolName.data.value.getOrElse(it) { 0x00 } }))
            else
                cryptography.hash(protocolName.data)
            val ck = ChainingKey(h)
            val state = CipherState(cryptography)
            SymmetricState(state, ck, HandshakeHash(h))
        }

        private val BLOCK_SIZE = Size(64)

        /** https://www.ietf.org/rfc/rfc2104.txt */
        private fun authenticateMessage(cryptography: Cryptography, key: MessageAuthenticationKey, data: Data) = let {

            fun block(init: (Int) -> Byte) = Data(ByteArray(BLOCK_SIZE.value, init))

            val keyData =
                if (key.data.size <= BLOCK_SIZE)
                    block { key.data.value.getOrElse(it) { 0x00 } }
                else cryptography.hash(key.data).data
            val innerPadding = block { 0x36 }
            val outerPadding = block { 0x5c }

            val digest =
                cryptography.hash(keyData.xor(outerPadding) + cryptography.hash(keyData.xor(innerPadding) + data).data)
            MessageAuthenticationData(digest)
        }

        internal fun deriveKeys(cryptography: Cryptography, key: ChainingKey, material: InputKeyMaterial) = let {
            val temporaryKey =
                authenticateMessage(cryptography, key.digest.messageAuthenticationKey, material.data)
            val output1 =
                authenticateMessage(cryptography, temporaryKey.digest.messageAuthenticationKey, Data(byteArrayOf(0x01)))
            val output2 = authenticateMessage(
                cryptography,
                temporaryKey.digest.messageAuthenticationKey,
                output1.digest.data + Data(byteArrayOf(0x02))
            )
            Pair(output1, output2)
        }
    }
}
