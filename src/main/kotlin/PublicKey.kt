package nl.sanderdijkhuis.noise

@JvmInline
value class PublicKey(val value: ByteArray) {

    val data get() = Data(value)
}
