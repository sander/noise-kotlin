package nl.sanderdijkhuis.noise

data class Symmetry(val cipher: Cipher, val key: ChainingKey, val handshakeHash: HandshakeHash) {

    @JvmInline
    value class ChainingKey(val digest: Digest)

    @JvmInline
    value class HandshakeHash(val digest: Digest)

    val cryptography get() = cipher.cryptography

    fun mixKey(inputKeyMaterial: InputKeyMaterial) = let {
        val (chainingKey, cipherKey) = deriveKeys(cryptography, key, inputKeyMaterial)
        copy(
            cipher = Cipher(cryptography = cryptography, key = cipherKey.cipherKey),
            key = ChainingKey(chainingKey.digest)
        )
    }

    fun mixHash(data: Data) = let {
        val result = copy(handshakeHash = HandshakeHash(cryptography.hash(handshakeHash.digest.data + data)))
        println("Mixing $handshakeHash + $data = ${result.handshakeHash}")
        result
    }

    fun encryptAndHash(plaintext: Plaintext) = let {
        println("Encrypting and hashing $handshakeHash $plaintext")
        cipher.encrypt(handshakeHash.digest.data, plaintext).let {
            State(copy(cipher = it.value).mixHash(it.result.data), it.result)
        }
    }

    fun decryptAndHash(ciphertext: Ciphertext) = let {
        println("Decrypting and hashing $handshakeHash $ciphertext")
        cipher.decrypt(handshakeHash.digest.data, ciphertext)?.let {
            State(copy(cipher = it.value).mixHash(ciphertext.data), it.result)
        }
    }

    fun split() = let {
        val zeroLen = InputKeyMaterial(Data.empty)
        val temporaryKeys = deriveKeys(cryptography, key, zeroLen)
        val c1 = Cipher(cryptography, temporaryKeys.first.cipherKey)
        val c2 = Cipher(cryptography, temporaryKeys.second.cipherKey)
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
            val state = Cipher(cryptography)
            Symmetry(state, ck, HandshakeHash(h))
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