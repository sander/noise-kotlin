package nl.sanderdijkhuis.noise

data class Transport(
    val initiatorCipherState: Cipher,
    val responderCipherState: Cipher,
    val handshakeHash: Digest
) : MessageType
