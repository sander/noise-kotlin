package nl.sanderdijkhuis.noise

import kotlin.experimental.xor

/** https://noiseprotocol.org/noise.html#hash-functions */
object HashFunction {

//    data class Hash(val data: Data) : HashFunction
//
//    data class AuthenticateMessage(val key: MessageAuthenticationKey, val data: Data) : HashFunction

//    companion object {

    /** https://www.ietf.org/rfc/rfc2104.txt */
    fun authenticateMessage(
        cryptography: Cryptography,
        key: MessageAuthenticationKey,
        data: Data
    ) = let {

        fun block(init: (Int) -> Byte) = Data(ByteArray(HashConfiguration.blockSize.value, init))

        val keyData =
            if (key.value.size <= HashConfiguration.blockSize.value)
                block { key.value.getOrElse(it) { 0x00 } }
            else cryptography.hash(key.data).data()
        val innerPadding = block { 0x36 }
        val outerPadding = block { 0x5c }

        val digest = cryptography.hash(keyData.xor(outerPadding) + cryptography.hash(keyData.xor(innerPadding) + data).data())
        MessageAuthenticationData(digest)
    }

    fun deriveKey2(cryptography: Cryptography, chainingKey: ChainingKey, inputKeyMaterial: InputKeyMaterial) = let {
        val temporaryKey = authenticateMessage(cryptography, chainingKey.messageAuthenticationKey(), inputKeyMaterial.data())
        val output1 = authenticateMessage(cryptography, temporaryKey.messageAuthenticationKey(), Data(byteArrayOf(0x01)))
        val output2 = authenticateMessage(cryptography, temporaryKey.messageAuthenticationKey(), output1.data() + Data(byteArrayOf(0x02)))
        Pair(output1, output2)
    }

    fun deriveKey3(cryptography: Cryptography, chainingKey: ChainingKey, inputKeyMaterial: InputKeyMaterial) = let {
        val temporaryKey = authenticateMessage(cryptography, chainingKey.messageAuthenticationKey(), inputKeyMaterial.data())
        val output1 = authenticateMessage(cryptography, temporaryKey.messageAuthenticationKey(), Data(byteArrayOf(0x01)))
        val output2 = authenticateMessage(cryptography, temporaryKey.messageAuthenticationKey(), output1.data() + Data(byteArrayOf(0x02)))
        val output3 = authenticateMessage(cryptography, temporaryKey.messageAuthenticationKey(), output2.data() + Data(byteArrayOf(0x03)))
        Triple(output1, output2, output3)
    }

    /** https://www.ietf.org/rfc/rfc2104.txt */
//    fun authenticateMessage(
//        hash: (Data) -> Digest,
//        key: MessageAuthenticationKey,
//        data: Data
//    ): MessageAuthenticationData = MessageAuthenticationData(let {
//        val keyData =
//            if (key.value.size <= HashConfiguration.blockSize.value)
//                ByteArray(HashConfiguration.blockSize.value) {
//                    key.value.getOrElse(it) { 0x00 }
//                }
//            else hash(key.data).value
//        val innerPadding = ByteArray(HashConfiguration.blockSize.value) { 0x36 }
//        val outerPadding = ByteArray(HashConfiguration.blockSize.value) { 0x5c }
//        fun ByteArray.xor(that: ByteArray) = Data(let {
//            require(size == that.size)
//            ByteArray(size) { this[it].xor(that[it]) }
//        })
//
//        operator fun Data.plus(that: Data) = Data(this.value + that.value)
//        fun Digest.data() = Data(this.value)
//        hash(keyData.xor(outerPadding) + hash(keyData.xor(innerPadding) + data).data()).value
//    })

//        sealed interface MessageAuthenticationResult {
//
//             too much hassle for a cheap function
//            data class RequiresHash(val hash: Hash, val continuation: (Digest) -> MessageAuthenticationResult) :
//                MessageAuthenticationResult
//        }
//    }
}
