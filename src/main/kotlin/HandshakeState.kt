package nl.sanderdijkhuis.noise

data class HandshakeState(
    val pattern: HandshakePattern,
    val role: Role,
    val symmetricState: SymmetricState,
    val messagePatterns: List<List<Token>>,
    val s: KeyPair? = null,
    val e: KeyPair? = null,
    val rs: PublicKey? = null,
    val re: PublicKey? = null
    // assume that all required keys are provided
) {

    // return InsufficientKeyMaterial | LastHandshakeMessage message c1 c2 | IntermediateHandshakeMessage message
    fun writeMessage(payload: Payload): State<HandshakeState, Message>? =
        let {
            val pattern = messagePatterns.first()
            val result = pattern.fold(
                State(
                    symmetricState,
                    Data(ByteArray(0))
                ) as State<SymmetricState, Data>?
            ) { state, token ->
                state?.let { s ->
                    when (token) {
                        Token.E -> e
                            ?.let { State(s.state.mixHash(it.public.data), s.value + it.public.data) }
                            ?.let {
                                it.state.encryptAndHash(payload.plainText)?.map { c -> it.value + c.data() }
                                    ?: State(it.state, it.value + payload.data)
                            }

                        else -> state
                    }
                }
            }
            result?.let {
                State(
                    copy(symmetricState = it.state, messagePatterns = messagePatterns.drop(1)),
                    Message(it.value.value)
                )
            }
        }

    enum class Role {
        INITIATOR, RESPONDER
    }

    enum class Token {
        E, S, EE, ES, SE, SS
    }

    companion object {

        fun initialize(
            cryptography: Cryptography,
            pattern: HandshakePattern, role: Role, prologue: Prologue,
            s: KeyPair?, e: KeyPair?, rs: PublicKey?, re: PublicKey?
        ) = let {
            val protocolName = ProtocolName(ByteArray(0)) // TODO
            val symmetricState = SymmetricState
                .initialize(cryptography, protocolName)
                .mixHash(prologue.data)
            // TODO mixHash for each public key listed in pre-messages
            HandshakeState(pattern, role, symmetricState, listOf(listOf(Token.E)))
        }
    }
}
