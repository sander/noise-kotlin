package nl.sanderdijkhuis.noise.cryptography

import nl.sanderdijkhuis.noise.data.Data

@JvmInline
value class PublicKey(val data: Data) {

    init {
        data.require(SharedSecret.SIZE)
    }

    val plaintext get() = Plaintext(data)
}
