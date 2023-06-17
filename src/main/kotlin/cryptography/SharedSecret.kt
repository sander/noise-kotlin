package nl.sanderdijkhuis.noise.cryptography

import nl.sanderdijkhuis.noise.data.Data
import nl.sanderdijkhuis.noise.data.Size

/** Outcome of Diffie-Hellman key agreement. */
@JvmInline
value class SharedSecret(val data: Data) {

    init {
        data.require(SIZE)
    }

    companion object {

        val SIZE = Size(32u)
    }
}
