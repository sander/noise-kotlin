package nl.sanderdijkhuis.noise.data

/** Size of a [Data] object. */
@JvmInline
value class Size(val value: UShort) {

    val integerValue get() = value.toInt()

    operator fun compareTo(size: Size) = value.compareTo(size.value)

    fun byteArray(f: (Int) -> Byte) = ByteArray(value.toInt(), f)

    operator fun plus(size: Size) = (value + size.value).takeIf { it <= UShort.MAX_VALUE }?.let { Size(it.toUShort()) }

    companion object {

        val MAX_MESSAGE = Size(UShort.MAX_VALUE)
    }
}
