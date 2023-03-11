package nl.sanderdijkhuis.noise.cryptography

import nl.sanderdijkhuis.noise.data.Data
import nl.sanderdijkhuis.noise.data.Size

@JvmInline
value class Digest(val data: Data) {

    init {
        data.require(SIZE)
    }

    companion object {

        val SIZE = Size(32)
    }
}
