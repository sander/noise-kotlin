package nl.sanderdijkhuis.noise

@JvmInline
value class Plaintext(val data: Data) {

    val ciphertext get() = Ciphertext(data)
}
