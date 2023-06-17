package nl.sanderdijkhuis.noise

import nl.sanderdijkhuis.noise.cryptography.Digest

/**
 * Initial transport message state.
 *
 * Be careful to increment [nonces][nl.sanderdijkhuis.noise.cryptography.Nonce] when sending new transport messages.
 */
data class Transport(
    val initiatorCipherState: Cipher,
    val responderCipherState: Cipher,
    val handshakeHash: Digest
) : MessageType
