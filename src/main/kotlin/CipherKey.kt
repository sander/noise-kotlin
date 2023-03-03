package nl.sanderdijkhuis.noise

import nl.sanderdijkhuis.noise.Size.Companion.valueSize

@JvmInline
value class CipherKey(val value: ByteArray) {

    init {
        require(value.valueSize == SIZE)
    }

    companion object {

        val SIZE = Size(32)
    }
}