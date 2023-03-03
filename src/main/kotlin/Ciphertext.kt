package nl.sanderdijkhuis.noise

@JvmInline
value class Ciphertext(val data: Data) {

    val plaintext get() = Plaintext(data)
}
