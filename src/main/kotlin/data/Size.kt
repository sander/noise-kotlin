package nl.sanderdijkhuis.noise.data

@JvmInline
value class Size(val value: Int) {

    operator fun compareTo(size: Size) = value.compareTo(size.value)

    init {
        println("Initializing Size with $value")
        require(value >= 0) { "Size too small" }
        require(value <= MAX_MESSAGE_LENGTH) { "Size too large (maximum is $MAX_MESSAGE_LENGTH)" }
    }

    fun byteArray(f: (Int) -> Byte) = ByteArray(value, f)

    companion object {

        private const val MAX_MESSAGE_LENGTH = 65535

        val MAX_MESSAGE = Size(MAX_MESSAGE_LENGTH)
    }
}
