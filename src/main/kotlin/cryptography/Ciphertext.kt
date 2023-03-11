package nl.sanderdijkhuis.noise.cryptography

import nl.sanderdijkhuis.noise.data.Data

@JvmInline
value class Ciphertext(val data: Data) {

    val plaintext get() = Plaintext(data)
}
