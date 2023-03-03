package nl.sanderdijkhuis.noise

@JvmInline
value class Digest(val data: Data) {

    init {
        require(data.size == HashFunction.HASH_SIZE)
    }

    val messageAuthenticationKey get() = MessageAuthenticationKey(data)
}
