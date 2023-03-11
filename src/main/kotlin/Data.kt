package nl.sanderdijkhuis.noise

import nl.sanderdijkhuis.noise.Size.Companion.valueSize
import kotlin.experimental.xor

data class Data(val value: ByteArray) {

    init {
        require(value.valueSize <= Size.MAX_MESSAGE)
    }

    operator fun plus(that: Data) = Data(this.value + that.value)

    val size get() = value.valueSize

    val isEmpty get() = value.isEmpty()

    fun xor(that: Data) = Data(let {
        require(value.size == that.value.size)
        ByteArray(value.size) { this.value[it] xor that.value[it] }
    })

    fun require(requiredSize: Size) {
        require(size == requiredSize) { "Invalid size, must be ${requiredSize.value}" }
    }

    override fun equals(other: Any?) =
        this === other || ((other as? Data)?.let { value.contentEquals(it.value) } ?: false)

    override fun hashCode() = value.contentHashCode()

    companion object {

        val empty get() = Data(ByteArray(0))
    }
}
