package nl.sanderdijkhuis.noise

@JvmInline
value class PublicKey(val data: Data) {

    init {
        require(data.size == SharedSecret.SIZE)
    }

    val plaintext get() = Plaintext(data)
}
