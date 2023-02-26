package nl.sanderdijkhuis.noise

@JvmInline
value class ChainingKey(val digest: Digest) {

    fun messageAuthenticationKey() = MessageAuthenticationKey(digest.value)
}
