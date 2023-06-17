package nl.sanderdijkhuis.noise.cryptography

import nl.sanderdijkhuis.noise.data.Data
import nl.sanderdijkhuis.noise.data.Size

/** Outcome of the hashing function. */
@JvmInline
value class Digest(val data: Data) {

    init {
        data.require(SIZE)
    }

    companion object {

        val SIZE = Size(32u)
    }
}
