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
        println("Writing ${messagePatterns.first()}")
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
        }?.runAndAppendInState { it.encryptAndHash(payload.plainText)?.map { c -> c.data() } }
            ?.map { Message(it.value) }
        val rest = messagePatterns.drop(1)
        when {
            state == null -> MessageResult.InsufficientKeyMaterial
            rest.isEmpty() -> symmetricState.split()
                .let { MessageResult.FinalHandshakeMessage(it.first, it.second, symmetricState.h, state.result) }

            else -> MessageResult.IntermediateHandshakeMessage(
                state.current.copy(messagePatterns = rest),
                state.result
            )
        }
    }

    fun readMessage(message: Message) = let {
        println("Reading ${messagePatterns.first()}")
        val init: State<HandshakeState, Data>? = State(this, Data(message.value))
        val state = messagePatterns.first().fold(init) { state, token ->
            fun mixKey(local: KeyPair?, remote: PublicKey?) = when {
                local == null || remote == null -> null
                else -> state?.run { s -> s.mixKey(cryptography.agree(local.private, remote).inputKeyMaterial) }
            }
            println("State $state")
            println("Token $token")
            when {
                state == null -> null
                token == Token.E && state.current.re == null ->
                    let {
                        val re =
                            PublicKey(
                                state.result.value.sliceArray(
                                    IntRange(
                                        0,
                                        KeyAgreementConfiguration.size.value - 1
                                    )
                                )
                            )
                        println("E: read $re")
                        val mixed = state.current.symmetricState.mixHash(re.data)
                        state.copy(
                            current = state.current.copy(symmetricState = mixed, re = re),
                            result = Data(state.result.value.drop(KeyAgreementConfiguration.size.value).toByteArray())
                        )
                    }

                token == Token.S && state.current.rs == null -> let {
                    println("S")
                    val splitAt = KeyAgreementConfiguration.size.value + 16
                    val temp =
                        state.result.value.sliceArray(IntRange(0, splitAt - 1))
                    state.current.symmetricState.decryptAndHash(Ciphertext(temp))?.let {
                        state.copy(
                            current = state.current.copy(symmetricState = it.current, rs = PublicKey(it.result.value)),
                            result = Data(
                                state.result.value.drop(splitAt).toByteArray()
                            )
                        )
                    }
                }

                token == Token.EE -> let {
                    println("EE: Mixing ${state.current.e} ${state.current.re}")
                    mixKey(state.current.e, state.current.re)
                }

                token == Token.ES && role == Role.INITIATOR -> mixKey(state.current.e, state.current.rs)
                token == Token.ES && role == Role.RESPONDER -> mixKey(state.current.s, state.current.re)
                token == Token.SE && role == Role.INITIATOR -> let {
                    println("SE")
                    mixKey(state.current.s, state.current.re)
                }

                token == Token.SE && role == Role.RESPONDER -> mixKey(state.current.e, state.current.rs)
                token == Token.SS -> mixKey(state.current.s, state.current.rs)
                else -> null
            }
        }?.let {
            it.current.symmetricState.decryptAndHash(Ciphertext(it.result.value))?.let { decrypted ->
                State(
                    it.current.copy(symmetricState = decrypted.current), Payload(
                        Data(decrypted.result.value)
                    )
                )
            }
        }

        val rest = messagePatterns.drop(1)
        when {
            state == null -> MessageResult.InsufficientKeyMaterial
            rest.isEmpty() -> symmetricState.split()
                .let { MessageResult.FinalHandshakeMessage(it.first, it.second, symmetricState.h, state.result) }

            else -> MessageResult.IntermediateHandshakeMessage(
                state.current.copy(messagePatterns = rest),
                state.result
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
            s: KeyPair? = null, e: KeyPair? = null, rs: PublicKey? = null, re: PublicKey? = null
        ): HandshakeState? {
            var state = SymmetricState.initialize(cryptography, pattern.name).mixHash(prologue.data)
            if (pattern.preSharedMessagePatterns.size > 0) {
                for (p in pattern.preSharedMessagePatterns[0]) {
                    if (p == Token.S && role == Role.INITIATOR && s != null) {
                        state = state.mixHash(s.public.data)
                    } else if (p == Token.S && role == Role.RESPONDER && rs != null) {
                        state = state.mixHash(rs.data)
                    } else {
                        return null
                    }
                }
            }
            if (pattern.preSharedMessagePatterns.size == 2) {
                for (p in pattern.preSharedMessagePatterns[1]) {
                    if (p == Token.S && role == Role.RESPONDER && s != null) {
                        state = state.mixHash(s.public.data)
                    } else if (p == Token.S && role == Role.INITIATOR && rs != null) {
                        state = state.mixHash(rs.data)
                    } else {
                        return null
                    }
                }
            }
            return HandshakeState(role, state, pattern.messagePatterns, s, e, rs, re)
        }
    }
}
