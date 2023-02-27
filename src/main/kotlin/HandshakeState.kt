package nl.sanderdijkhuis.noise

data class HandshakeState(
    val role: Role,
    val symmetricState: SymmetricState,
    val messagePatterns: List<List<Token>>,
    val s: KeyPair? = null,
    val e: KeyPair? = null,
    val rs: PublicKey? = null,
    val re: PublicKey? = null
    // assume that all required keys are provided
) {

    private val cryptography get() = symmetricState.cryptography

    private fun State<HandshakeState, Data>.run(
        d: Data = Data.empty(),
        f: (SymmetricState) -> SymmetricState
    ) =
        copy(current = current.copy(symmetricState = f(current.symmetricState)), result = result + d)

    private fun State<HandshakeState, Data>.runAndAppendInState(
        f: (SymmetricState) -> State<SymmetricState, Data>?
    ) =
        f(current.symmetricState)?.let { s -> State(current.copy(symmetricState = s.current), result + s.result) }

    fun writeMessage(payload: Payload) = let {
        val init: State<HandshakeState, Data>? = State(this, Data.empty())
        val state = messagePatterns.first().fold(init) { state, token ->
            fun mixKey(local: KeyPair?, remote: PublicKey?) = when {
                local == null || remote == null -> null
                else -> state?.run { s -> s.mixKey(cryptography.agree(local.private, remote).inputKeyMaterial) }
            }
            when {
                state == null -> null
                token == Token.E && e != null -> state.run(e.public.data) { it.mixHash(e.public.data) }
                token == Token.S && s != null -> state.runAndAppendInState {
                    it.encryptAndHash(s.public.plaintext).map { c -> c.data() }
                }

                token == Token.EE -> mixKey(e, re)
                token == Token.ES && role == Role.INITIATOR -> mixKey(e, rs)
                token == Token.ES && role == Role.RESPONDER -> mixKey(s, re)
                token == Token.SE && role == Role.INITIATOR -> mixKey(s, re)
                token == Token.SE && role == Role.RESPONDER -> mixKey(e, rs)
                token == Token.SS -> mixKey(s, rs)
                else -> null
            }
        }?.runAndAppendInState { it.encryptAndHash(payload.plainText)?.map { c -> c.data() } }?.map { Message(it.value) }
        val rest = messagePatterns.drop(1)
        when {
            state == null -> MessageResult.InsufficientKeyMaterial
            rest.isEmpty() -> symmetricState.split()
                .let { MessageResult.FinalHandshakeMessage(it.first, it.second, state.result) }

            else -> MessageResult.IntermediateHandshakeMessage(
                state.current.copy(messagePatterns = rest),
                state.result
            )
        }
    }

    fun readMessage(message: Message): MessageResult? = TODO()

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
            s: KeyPair? = null, e: KeyPair? = null, rs: PublicKey? = null, re: PublicKey? = null
        ) = let {
            val symmetricState = SymmetricState
                .initialize(cryptography, pattern.name)
                .mixHash(prologue.data)
            // TODO mixHash for each public key listed in pre-messages
            HandshakeState(role, symmetricState, pattern.messagePatterns, s, e, rs, re)
        }
    }
}
