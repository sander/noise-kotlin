package nl.sanderdijkhuis.noise.cryptography

import nl.sanderdijkhuis.noise.data.Data

/** For use in Authenticated Encryption with Associated Data. */
@JvmInline
value class AssociatedData(val data: Data)
