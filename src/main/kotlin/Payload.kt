package nl.sanderdijkhuis.noise

import nl.sanderdijkhuis.noise.data.Data

/** Plaintext handshake payload. */
@JvmInline
value class Payload(val data: Data)
