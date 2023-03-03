package nl.sanderdijkhuis.noise

sealed interface MessageResult<T> {

    object InsufficientKeyMaterial : MessageResult<Nothing>

    data class IntermediateHandshakeMessage<T>(val state: HandshakeState, val result: T) : MessageResult<T>

    data class FinalHandshakeMessage<T>(
        val initiatorCipherState: CipherState,
        val responderCipherState: CipherState,
        val handshakeHash: HandshakeHash,
        val result: T
    ) : MessageResult<T>
}
