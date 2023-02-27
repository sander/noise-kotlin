package nl.sanderdijkhuis.noise

import kotlin.experimental.xor

@JvmInline
value class Data(val value: ByteArray) {

    operator fun plus(that: Data) = Data(this.value + that.value)

    fun xor(that: Data) = Data(let {
        require(value.size == that.value.size)
        ByteArray(value.size) { this.value[it].xor(that.value[it]) }
    })

    companion object {

        fun empty() = Data(ByteArray(0))
    }
}
