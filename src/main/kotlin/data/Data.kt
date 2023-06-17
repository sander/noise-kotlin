package nl.sanderdijkhuis.noise.data

import kotlin.experimental.xor

/** Immutable binary data. */
data class Data(val value: ByteArray) {

    init {
        require(value.size <= Size.MAX_MESSAGE.integerValue)
    }

    operator fun plus(that: Data) = Data(this.value + that.value)

    val size get() = Size(value.size.toUShort())

    val isEmpty get() = value.isEmpty()

    fun xor(that: Data) = Data(let {
        require(value.size == that.value.size)
        ByteArray(value.size) { this.value[it] xor that.value[it] }
    })

    fun require(requiredSize: Size) {
        require(size == requiredSize) { "Invalid size, must be ${requiredSize.value}" }
    }

    fun readFirst(size: Size): Pair<Data, Data>? = if (this.size >= size) let {
        val first = value.sliceArray(IntRange(0, size.integerValue - 1))
        val second = value.sliceArray(IntRange(size.integerValue, value.size - 1))
        Pair(Data(first), Data(second))
    } else null

    override fun equals(other: Any?) =
        this === other || ((other as? Data)?.let { value.contentEquals(it.value) } ?: false)

    override fun hashCode() = value.contentHashCode()

    companion object {

        val empty get() = Data(ByteArray(0))
    }
}
