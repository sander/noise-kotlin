package nl.sanderdijkhuis.noise

import nl.sanderdijkhuis.noise.Size.Companion.valueSize
import kotlin.experimental.xor

@JvmInline
value class Data(val value: ByteArray) {

    init {
        require(value.valueSize <= Size.MAX_MESSAGE)
    }

    operator fun plus(that: Data) = Data(this.value + that.value)

    val size get() = value.valueSize

    fun xor(that: Data) = Data(let {
        require(value.size == that.value.size)
        ByteArray(value.size) { this.value[it].xor(that.value[it]) }
    })

    companion object {

        val empty get() = Data(ByteArray(0))
    }
}
