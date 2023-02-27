package nl.sanderdijkhuis.noise

@JvmInline
value class Plaintext(val value: ByteArray) {

    val ciphertext get() = Ciphertext(value)
}
