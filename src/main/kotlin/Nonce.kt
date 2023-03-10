package nl.sanderdijkhuis.noise

import nl.sanderdijkhuis.noise.Size.Companion.valueSize
import java.nio.ByteBuffer
import java.nio.ByteOrder

@JvmInline
value class Nonce(val value: ByteArray) {

    init {
        require(value.valueSize == SIZE)
    }

    constructor(number: ULong) : this(
        ByteBuffer.allocate(SIZE.value).order(ByteOrder.BIG_ENDIAN).putLong(number.toLong()).array()
    )

    fun increment() =
        if (value.contentEquals(SIZE.byteArray { 0xff.toByte() })) null
        else Nonce(ByteBuffer.wrap(value).order(ByteOrder.BIG_ENDIAN).long.toULong() + 1u)

    fun toULong() = ByteBuffer.wrap(value).order(ByteOrder.BIG_ENDIAN).long.toULong()

    companion object {

        val SIZE = Size(8)

        val zero get() = Nonce(SIZE.byteArray { 0x00 })
    }
}
