package nl.sanderdijkhuis.noise

@JvmInline
value class Digest(val data: Data) {

    init {
        require(data.size == SIZE)
    }

    val messageAuthenticationKey get() = MessageAuthenticationKey(data)

    companion object {

        val SIZE = Size(32)
    }
}
