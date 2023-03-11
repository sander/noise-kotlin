package nl.sanderdijkhuis.noise.data

@JvmInline
value class Size(val value: UShort) {

    val integerValue get() = value.toInt()

    operator fun compareTo(size: Size) = value.compareTo(size.value)

    fun byteArray(f: (Int) -> Byte) = ByteArray(value.toInt(), f)

    companion object {

        val MAX_MESSAGE = Size(UShort.MAX_VALUE)
    }
}
