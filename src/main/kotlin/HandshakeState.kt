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

    // return InsufficientKeyMaterial | LastHandshakeMessage message c1 c2 | IntermediateHandshakeMessage message state
    // writeMessage(payload: Payload: keyPair: KeyPair) // for new e messages
    fun writeMessage(payload: Payload): State<HandshakeState, Message>? =
        let {
            val pattern = messagePatterns.first()
            val result = pattern.fold(
                State(symmetricState, Data(ByteArray(0))) as State<SymmetricState, Data>?
            ) { state, token ->
                when {
                    state == null -> null
                    token == Token.E && e != null -> let {
                        val mixed = state.state.mixHash(e.public.data)
                        val buffer = state.value + e.public.data

                        // TODO later
                        mixed.encryptAndHash(payload.plainText)?.map { c -> buffer + c.data() }
                            ?: state.copy(value = buffer + payload.data)
                    }

//                    State(
//                        state.state.mixHash(e.public.data),
//                        state.value + e.public.data
//                    ).let {
//                        it.state.encryptAndHash(payload.plainText)?.map { c -> it.value + c.data() }
//                            ?: it.copy(value = it.value + payload.data)
//                    }

                    else -> state
                }
//                state?.let { s ->
//                    when (token) {
//                        Token.E -> e
//                            ?.let { State(s.state.mixHash(it.public.data), s.value + it.public.data) }
//                            ?.let {
//                                it.state.encryptAndHash(payload.plainText)?.map { c -> it.value + c.data() }
//                                    ?: State(it.state, it.value + payload.data)
//                            }
//
//                        else -> state
//                    }
//                }
            }
            result?.let {
                State(
                    copy(symmetricState = it.state, messagePatterns = messagePatterns.drop(1)),
                    Message(it.value.value)
                )
            }
        }

    sealed interface MessageResult {

        object InsufficientKeyMaterial : MessageResult

        data class IntermediateHandshakeMessage(val state: HandshakeState, val message: Message) : MessageResult

        data class FinalHandshakeMessage(
            val cipherState1: CipherState,
            val cipherState2: CipherState,
            val message: Message
        ) : MessageResult
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
