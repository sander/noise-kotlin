package nl.sanderdijkhuis.noise

sealed interface MessageResult<T> {

    object InsufficientKeyMaterial : MessageResult<Nothing>

    data class IntermediateHandshakeMessage<T>(val state: HandshakeState, val result: T) : MessageResult<T>

    data class FinalHandshakeMessage<T>(
        val cipherState1: CipherState,
        val cipherState2: CipherState,
        val result: T
    ) : MessageResult<T>
}