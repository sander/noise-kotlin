package nl.sanderdijkhuis.noise

@JvmInline
value class Size(val value: Int) {

    operator fun compareTo(size: Size) = value.compareTo(size.value)

    init {
        require(value <= MAX_MESSAGE)
    }

    companion object {

        const val MAX_MESSAGE = 65535
    }
}