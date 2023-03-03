package nl.sanderdijkhuis.noise

@JvmInline
value class Ciphertext(val value: ByteArray) {

    val data get() = Data(value)

    val plaintext get() = Plaintext(value)
}
