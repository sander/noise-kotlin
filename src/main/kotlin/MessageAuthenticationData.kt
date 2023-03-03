package nl.sanderdijkhuis.noise

@JvmInline
value class MessageAuthenticationData(val digest: Digest) {

    val cipherKey get() = CipherKey(digest.data.value)

    val chainingKey get() = ChainingKey(digest)
}
