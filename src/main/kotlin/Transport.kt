package nl.sanderdijkhuis.noise

import nl.sanderdijkhuis.noise.cryptography.Digest

data class Transport(
    val initiatorCipherState: Cipher,
    val responderCipherState: Cipher,
    val handshakeHash: Digest
) : MessageType
