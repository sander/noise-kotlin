package nl.sanderdijkhuis.noise

@JvmInline
value class AssociatedData(private val value: ByteArray) {

    init {
        require(value.size <= MAX_SIZE)
    }

    companion object {

        const val MAX_SIZE = Size.MAX_MESSAGE
    }
}