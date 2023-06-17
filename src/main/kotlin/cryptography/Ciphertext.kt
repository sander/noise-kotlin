package nl.sanderdijkhuis.noise.cryptography

import nl.sanderdijkhuis.noise.data.Data

/** Result of Authenticated Encryption with Associated Data, or of no-op encryption. */
@JvmInline
value class Ciphertext(val data: Data) {

    val plaintext get() = Plaintext(data)
}
