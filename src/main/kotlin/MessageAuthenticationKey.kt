package nl.sanderdijkhuis.noise

@JvmInline
value class MessageAuthenticationKey(val value: ByteArray) {

    val data get() = Data(value)
}
