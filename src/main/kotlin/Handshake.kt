package nl.sanderdijkhuis.noise

data class Handshake(
    val role: Role,
    val symmetry: Symmetry,
    val messagePatterns: List<List<Token>>,
    val localStaticKeyPair: KeyPair? = null,
    val localEphemeralKeyPair: KeyPair? = null,
    val remoteStaticKey: PublicKey? = null,
    val remoteEphemeralKey: PublicKey? = null,
    val trustedStaticKeys: Set<PublicKey> = emptySet()
) {

    private val cryptography get() = symmetry.cryptography

    private fun State<Handshake, Data>.run(
        d: Data = Data.empty,
        f: (Symmetry) -> Symmetry
    ) =
        copy(value = value.copy(symmetry = f(value.symmetry)), result = result + d)

    private fun State<Handshake, Data>.runAndAppendInState(
        f: (Symmetry) -> State<Symmetry, Data>?
    ) =
        f(value.symmetry)?.let { s -> State(value.copy(symmetry = s.value), result + s.result) }

    fun writeMessage(payload: Payload) = let {
        val init: State<Handshake, Data>? = State(this, Data.empty)
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
            rest.isEmpty() -> symmetry.split()
                .let {
                    MessageResult.FinalHandshakeMessage(
                        it.first,
                        it.second,
                        symmetry.handshakeHash.digest,
                        state.result
                    )
                }

            else -> MessageResult.IntermediateHandshakeMessage(
                state.value.copy(messagePatterns = rest),
                state.result
            )
        }
    }

    fun readMessage(message: Message) = let {
        println("Reading ${messagePatterns.first()}")
        val init: State<Handshake, Data>? = State(this, message.data)
        val state = messagePatterns.first().fold(init) { state, token ->
            fun mixKey(local: KeyPair?, remote: PublicKey?) = when {
                local == null || remote == null -> null
                else -> state?.run { s -> s.mixKey(cryptography.agree(local.private, remote).inputKeyMaterial) }
            }
            println("State $state")
            println("Token $token")
            when {
                state == null -> null
                token == Token.E && state.value.remoteEphemeralKey == null ->
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
                        val mixed = state.value.symmetry.mixHash(re.data)
                        state.copy(
                            value = state.value.copy(symmetry = mixed, remoteEphemeralKey = re),
                            result = Data(state.result.value.drop(SharedSecret.SIZE.value).toByteArray())
                        )
                    }

                token == Token.S && state.value.remoteStaticKey == null -> let {
                    println("S")
                    val splitAt = SharedSecret.SIZE.value + 16
                    val temp =
                        state.result.value.sliceArray(IntRange(0, splitAt - 1))
                    state.value.symmetry.decryptAndHash(Ciphertext(Data(temp)))?.let {
                        val publicKey = PublicKey(it.result.data)
                        println("Public key $publicKey")
                        println("Trusting $trustedStaticKeys")
                        println("Trusted? ${trustedStaticKeys.contains(publicKey)}")
                        if (trustedStaticKeys.contains(publicKey))
                            state.copy(
                                value = state.value.copy(symmetry = it.value, remoteStaticKey = publicKey),
                                result = Data(
                                    state.result.value.drop(splitAt).toByteArray()
                                )
                            )
                        else null
                    }
                }

                token == Token.EE -> let {
                    println("EE: Mixing ${state.value.localEphemeralKeyPair} ${state.value.remoteEphemeralKey}")
                    mixKey(state.value.localEphemeralKeyPair, state.value.remoteEphemeralKey)
                }

                token == Token.ES && role == Role.INITIATOR -> mixKey(state.value.localEphemeralKeyPair, state.value.remoteStaticKey)
                token == Token.ES && role == Role.RESPONDER -> mixKey(state.value.localStaticKeyPair, state.value.remoteEphemeralKey)
                token == Token.SE && role == Role.INITIATOR -> let {
                    println("SE")
                    mixKey(state.value.localStaticKeyPair, state.value.remoteEphemeralKey)
                }

                token == Token.SE && role == Role.RESPONDER -> mixKey(state.value.localEphemeralKeyPair, state.value.remoteStaticKey)
                token == Token.SS -> mixKey(state.value.localStaticKeyPair, state.value.remoteStaticKey)
                else -> null
            }
        }?.let {
            it.value.symmetry.decryptAndHash(Ciphertext(it.result))?.let { decrypted ->
                State(
                    it.value.copy(symmetry = decrypted.value), Payload(
                        decrypted.result.data
                    )
                )
            }
        }

        val rest = messagePatterns.drop(1)
        when {
            state == null -> MessageResult.InsufficientKeyMaterial
            rest.isEmpty() -> symmetry.split()
                .let {
                    MessageResult.FinalHandshakeMessage(
                        it.first,
                        it.second,
                        symmetry.handshakeHash.digest,
                        state.result
                    )
                }

            else -> MessageResult.IntermediateHandshakeMessage(
                state.value.copy(messagePatterns = rest),
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
        ): Handshake? {
            var state = Symmetry.initialize(cryptography, pattern.name).mixHash(prologue.data)
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
            return Handshake(role, state, pattern.messagePatterns, s, e, rs, re, trustedStaticKeys)
        }
    }
}
