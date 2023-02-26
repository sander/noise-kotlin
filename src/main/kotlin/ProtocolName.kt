package nl.sanderdijkhuis.noise

@JvmInline
value class ProtocolName(val value: ByteArray) {

    fun data() = Data(value)
}
