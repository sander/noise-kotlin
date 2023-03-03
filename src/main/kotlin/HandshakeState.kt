package nl.sanderdijkhuis.noise

data class HandshakeState(
    val role: Role,
    val symmetricState: SymmetricState,
    val messagePatterns: List<List<Token>>,
    val localStaticKeyPair: KeyPair? = null,
    val localEphemeralKeyPair: KeyPair? = null,
    val remoteStaticKey: PublicKey? = null,
    val remoteEphemeralKey: PublicKey? = null,
    val trustedStaticKeys: Set<PublicKey> = emptySet()
) {

    private val cryptography get() = symmetricState.cryptography

    private fun State<HandshakeState, Data>.run(
        d: Data = Data.empty,
        f: (SymmetricState) -> SymmetricState
    ) =
        copy(current = current.copy(symmetricState = f(current.symmetricState)), result = result + d)

    private fun State<HandshakeState, Data>.runAndAppendInState(
        f: (SymmetricState) -> State<SymmetricState, Data>?
    ) =
        f(current.symmetricState)?.let { s -> State(current.copy(symmetricState = s.current), result + s.result) }

    fun writeMessage(payload: Payload) = let {
        val init: State<HandshakeState, Data>? = State(this, Data.empty)
        println("Writing ${messagePatterns.first()}")
        val state = messagePatterns.first().fold(init) { state, token ->
            fun mixKey(local: KeyPair?, remote: PublicKey?) = when {
                local == null || remote == null -> null
                else -> state?.run { s -> s.mixKey(cryptography.agree(local.private, remote).inputKeyMaterial) }
            }
            when {
                state == null -> null
                token == Token.E && localEphemeralKeyPair != null -> state.run(localEphemeralKeyPair.public.data) { it.mixHash(localEphemeralKeyPair.public.data) }
                token == Token.S && localStaticKeyPair != null -> state.runAndAppendInState {
                    it.encryptAndHash(localStaticKeyPair.public.plaintext).map { c -> c.data }
                }

                token == Token.EE -> mixKey(localEphemeralKeyPair, remoteEphemeralKey)
                token == Token.ES && role == Role.INITIATOR -> mixKey(localEphemeralKeyPair, remoteStaticKey)
                token == Token.ES && role == Role.RESPONDER -> mixKey(localStaticKeyPair, remoteEphemeralKey)
                token == Token.SE && role == Role.INITIATOR -> mixKey(localStaticKeyPair, remoteEphemeralKey)
                token == Token.SE && role == Role.RESPONDER -> mixKey(localEphemeralKeyPair, remoteStaticKey)
                token == Token.SS -> mixKey(localStaticKeyPair, remoteStaticKey)
                else -> null
            }
        }?.runAndAppendInState { it.encryptAndHash(payload.plainText).map { c -> c.data } }
            ?.map { Message(it) }
        val rest = messagePatterns.drop(1)
        when {
            state == null -> MessageResult.InsufficientKeyMaterial
            rest.isEmpty() -> symmetricState.split()
                .let {
                    MessageResult.FinalHandshakeMessage(
                        it.first,
                        it.second,
                        symmetricState.handshakeHash,
                        state.result
                    )
                }

            else -> MessageResult.IntermediateHandshakeMessage(
                state.current.copy(messagePatterns = rest),
                state.result
            )
        }
    }

    fun readMessage(message: Message) = let {
        println("Reading ${messagePatterns.first()}")
        val init: State<HandshakeState, Data>? = State(this, message.data)
        val state = messagePatterns.first().fold(init) { state, token ->
            fun mixKey(local: KeyPair?, remote: PublicKey?) = when {
                local == null || remote == null -> null
                else -> state?.run { s -> s.mixKey(cryptography.agree(local.private, remote).inputKeyMaterial) }
            }
            println("State $state")
            println("Token $token")
            when {
                state == null -> null
                token == Token.E && state.current.remoteEphemeralKey == null ->
                    let {
                        val re =
                            PublicKey(
                                Data(
                                    state.result.value.sliceArray(
                                        IntRange(
                                            0,
                                            SharedSecret.SIZE.value - 1
                                        )
                                    )
                                )
                            )
                        println("E: read $re")
                        val mixed = state.current.symmetricState.mixHash(re.data)
                        state.copy(
                            current = state.current.copy(symmetricState = mixed, remoteEphemeralKey = re),
                            result = Data(state.result.value.drop(SharedSecret.SIZE.value).toByteArray())
                        )
                    }

                token == Token.S && state.current.remoteStaticKey == null -> let {
                    println("S")
                    val splitAt = SharedSecret.SIZE.value + 16
                    val temp =
                        state.result.value.sliceArray(IntRange(0, splitAt - 1))
                    state.current.symmetricState.decryptAndHash(Ciphertext(Data(temp)))?.let {
                        val publicKey = PublicKey(it.result.data)
                        println("Public key $publicKey")
                        println("Trusting $trustedStaticKeys")
                        println("Trusted? ${trustedStaticKeys.contains(publicKey)}")
                        if (trustedStaticKeys.contains(publicKey))
                            state.copy(
                                current = state.current.copy(symmetricState = it.current, remoteStaticKey = publicKey),
                                result = Data(
                                    state.result.value.drop(splitAt).toByteArray()
                                )
                            )
                        else null
                    }
                }

                token == Token.EE -> let {
                    println("EE: Mixing ${state.current.localEphemeralKeyPair} ${state.current.remoteEphemeralKey}")
                    mixKey(state.current.localEphemeralKeyPair, state.current.remoteEphemeralKey)
                }

                token == Token.ES && role == Role.INITIATOR -> mixKey(state.current.localEphemeralKeyPair, state.current.remoteStaticKey)
                token == Token.ES && role == Role.RESPONDER -> mixKey(state.current.localStaticKeyPair, state.current.remoteEphemeralKey)
                token == Token.SE && role == Role.INITIATOR -> let {
                    println("SE")
                    mixKey(state.current.localStaticKeyPair, state.current.remoteEphemeralKey)
                }

                token == Token.SE && role == Role.RESPONDER -> mixKey(state.current.localEphemeralKeyPair, state.current.remoteStaticKey)
                token == Token.SS -> mixKey(state.current.localStaticKeyPair, state.current.remoteStaticKey)
                else -> null
            }
        }?.let {
            it.current.symmetricState.decryptAndHash(Ciphertext(it.result))?.let { decrypted ->
                State(
                    it.current.copy(symmetricState = decrypted.current), Payload(
                        decrypted.result.data
                    )
                )
            }
        }

        val rest = messagePatterns.drop(1)
        when {
            state == null -> MessageResult.InsufficientKeyMaterial
            rest.isEmpty() -> symmetricState.split()
                .let {
                    MessageResult.FinalHandshakeMessage(
                        it.first,
                        it.second,
                        symmetricState.handshakeHash,
                        state.result
                    )
                }

            else -> MessageResult.IntermediateHandshakeMessage(
                state.current.copy(messagePatterns = rest),
                state.result
            )
        }
    }

    companion object {

        fun initialize(
            cryptography: Cryptography,
            pattern: HandshakePattern, role: Role, prologue: Prologue,
            s: KeyPair? = null, e: KeyPair? = null, rs: PublicKey? = null, re: PublicKey? = null,
            trustedStaticKeys: Set<PublicKey> = emptySet()
        ): HandshakeState? {
            var state = SymmetricState.initialize(cryptography, pattern.name).mixHash(prologue.data)
            if (pattern.preSharedMessagePatterns.isNotEmpty()) {
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
            return HandshakeState(role, state, pattern.messagePatterns, s, e, rs, re, trustedStaticKeys)
        }
    }
}
