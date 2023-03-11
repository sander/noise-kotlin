package nl.sanderdijkhuis.noise

sealed interface MessageResult<T> {

    object InsufficientKeyMaterial : MessageResult<Nothing>

    data class IntermediateHandshakeMessage<T>(val state: Handshake, val result: T) : MessageResult<T>

    data class FinalHandshakeMessage<T>(
        val initiatorCipherState: Cipher,
        val responderCipherState: Cipher,
        val handshakeHash: Digest,
        val result: T
    ) : MessageResult<T>
}
