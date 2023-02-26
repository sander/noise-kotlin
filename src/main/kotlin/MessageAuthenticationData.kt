package nl.sanderdijkhuis.noise

@JvmInline
value class MessageAuthenticationData(val digest: Digest) {

    fun messageAuthenticationKey() = MessageAuthenticationKey(digest.value)

    fun cipherKey() = CipherKey(digest.value)

    fun data() = Data(digest.value)

    fun chainingKey() = ChainingKey(digest)
}
