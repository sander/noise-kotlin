package nl.sanderdijkhuis.noise

@JvmInline
value class Nonce(private val value: ByteArray) {

    init {
        require(value.size == SIZE)
    }

    companion object {

        const val SIZE = 8

        fun zero() = Nonce(ByteArray(SIZE) { 0x00 })
    }
}
