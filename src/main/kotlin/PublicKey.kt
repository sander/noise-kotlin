package nl.sanderdijkhuis.noise

@JvmInline
value class PublicKey(val data: Data) {

    init {
        data.require(SharedSecret.SIZE)
    }

    val plaintext get() = Plaintext(data)
}
