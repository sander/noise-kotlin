package nl.sanderdijkhuis.noise

@JvmInline
value class Ciphertext(val value: ByteArray) {

    fun data() = Data(value)

    val plaintext get() = Plaintext(value)
}
