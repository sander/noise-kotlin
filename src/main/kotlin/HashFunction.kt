package nl.sanderdijkhuis.noise

/** https://noiseprotocol.org/noise.html#hash-functions */
internal object HashFunction {

    val HASH_SIZE = Size(32)

    private val BLOCK_SIZE = Size(64)

    /** https://www.ietf.org/rfc/rfc2104.txt */
    private fun authenticateMessage(
        cryptography: Cryptography,
        key: MessageAuthenticationKey,
        data: Data
    ) = let {

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

    fun deriveKeys(cryptography: Cryptography, chainingKey: ChainingKey, inputKeyMaterial: InputKeyMaterial) = let {
        val temporaryKey =
            authenticateMessage(cryptography, chainingKey.digest.messageAuthenticationKey, inputKeyMaterial.data)
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
