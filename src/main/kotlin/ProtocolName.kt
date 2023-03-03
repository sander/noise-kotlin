package nl.sanderdijkhuis.noise

import nl.sanderdijkhuis.noise.Size.Companion.valueSize

@JvmInline
value class ProtocolName(val value: ByteArray) {

    val data get() = Data(value)

    val size get() = value.valueSize
}
