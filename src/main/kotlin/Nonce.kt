package nl.sanderdijkhuis.noise

import java.nio.ByteBuffer
import java.nio.ByteOrder

@JvmInline
value class Nonce(val value: ByteArray) {

    init {
        require(value.size == SIZE)
    }

    constructor(number: Long) : this(ByteBuffer.allocate(SIZE).order(ByteOrder.BIG_ENDIAN).putLong(number).array())

    fun increment() = Nonce(ByteBuffer.wrap(value).order(ByteOrder.BIG_ENDIAN).long + 1L)

    companion object {

        const val SIZE = 8

        fun zero() = Nonce(ByteArray(SIZE) { 0x00 })
    }
}
