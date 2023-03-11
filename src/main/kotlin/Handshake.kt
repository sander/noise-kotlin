package nl.sanderdijkhuis.noise

import nl.sanderdijkhuis.noise.cryptography.*
import nl.sanderdijkhuis.noise.data.Data
import nl.sanderdijkhuis.noise.data.State

data class Handshake(
    val role: Role,
    val symmetry: Symmetry,
    val messagePatterns: List<List<Token>>,
    val localStaticKeyPair: Pair<PublicKey, PrivateKey>? = null,
    val localEphemeralKeyPair: Pair<PublicKey, PrivateKey>? = null,
    val remoteStaticKey: PublicKey? = null,
    val remoteEphemeralKey: PublicKey? = null,
    val trustedStaticKeys: Set<PublicKey> = emptySet()
) : MessageType {

    data class Pattern(
        val name: String,
        val preSharedMessagePatterns: List<List<Token>>,
        val messagePatterns: List<List<Token>>
    )

    enum class Token {
        E, S, EE, ES, SE, SS
    }

    private val cryptography get() = symmetry.cryptography

    private fun State<Handshake, Data>.run(
        d: Data = nl.sanderdijkhuis.noise.data.Data.empty,
        f: (Symmetry) -> Symmetry
    ) =
        copy(value = value.copy(symmetry = f(value.symmetry)), result = result + d)

    private fun State<Handshake, Data>.runAndAppendInState(
        f: (Symmetry) -> State<Symmetry, Data>?
    ) =
        f(value.symmetry)?.let { s -> State(value.copy(symmetry = s.value), result + s.result) }

    fun writeMessage(payload: Payload): State<out MessageType, Data>? = let {
        val init: State<Handshake, Data>? = State(this, Data.empty)
        val state = messagePatterns.first().fold(init) { state, token ->
            fun mixKey(local: Pair<PublicKey, PrivateKey>?, remote: PublicKey?) = when {
                local == null || remote == null -> null
                else -> state?.run { s -> s.mixKey(cryptography.agree(local.second, remote)) }
            }
            when {
                state == null -> null
                token == Token.E && localEphemeralKeyPair != null -> state.run(localEphemeralKeyPair.first.data) {
                    it.mixHash(
                        localEphemeralKeyPair.first.data
                    )
                }

                token == Token.S && localStaticKeyPair != null -> state.runAndAppendInState {
                    it.encryptAndHash(localStaticKeyPair.first.plaintext).map { c -> c.data }
                }

                token == Token.EE -> mixKey(localEphemeralKeyPair, remoteEphemeralKey)
                token == Token.ES && role == Role.INITIATOR -> mixKey(localEphemeralKeyPair, remoteStaticKey)
                token == Token.ES && role == Role.RESPONDER -> mixKey(localStaticKeyPair, remoteEphemeralKey)
                token == Token.SE && role == Role.INITIATOR -> mixKey(localStaticKeyPair, remoteEphemeralKey)
                token == Token.SE && role == Role.RESPONDER -> mixKey(localEphemeralKeyPair, remoteStaticKey)
                token == Token.SS -> mixKey(localStaticKeyPair, remoteStaticKey)
                else -> null
            }
        }?.runAndAppendInState { it.encryptAndHash(Plaintext(payload.data)).map { c -> c.data } }
        val rest = messagePatterns.drop(1)
        when {
            state == null -> null
            rest.isEmpty() -> symmetry.split()
                .let {
                    State(
                        Transport(
                            it.first,
                            it.second,
                            symmetry.handshakeHash.digest
                        ),
                        state.result
                    )
                }

            else -> State(state.value.copy(messagePatterns = rest), state.result)
        }
    }

    fun readMessage(data: Data): State<out MessageType, Payload>? = let {
        val init: State<Handshake, Data>? = State(this, data)
        val state = messagePatterns.first().fold(init) { state, token ->
            fun mixKey(local: Pair<PublicKey, PrivateKey>?, remote: PublicKey?) = when {
                local == null || remote == null -> null
                else -> state?.run { s -> s.mixKey(cryptography.agree(local.second, remote)) }
            }
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
                                            SharedSecret.SIZE.value.toInt() - 1
                                        )
                                    )
                                )
                            )
                        val mixed = state.value.symmetry.mixHash(re.data)
                        state.copy(
                            value = state.value.copy(symmetry = mixed, remoteEphemeralKey = re),
                            result = Data(state.result.value.drop(SharedSecret.SIZE.integerValue).toByteArray())
                        )
                    }

                token == Token.S && state.value.remoteStaticKey == null -> let {
                    val splitAt = SharedSecret.SIZE.value.toInt() + 16
                    val temp =
                        state.result.value.sliceArray(IntRange(0, splitAt - 1))
                    state.value.symmetry.decryptAndHash(Ciphertext(Data(temp)))?.let {
                        val publicKey = PublicKey(it.result.data)
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
                    mixKey(state.value.localEphemeralKeyPair, state.value.remoteEphemeralKey)
                }

                token == Token.ES && role == Role.INITIATOR -> mixKey(
                    state.value.localEphemeralKeyPair,
                    state.value.remoteStaticKey
                )

                token == Token.ES && role == Role.RESPONDER -> mixKey(
                    state.value.localStaticKeyPair,
                    state.value.remoteEphemeralKey
                )

                token == Token.SE && role == Role.INITIATOR -> let {
                    mixKey(state.value.localStaticKeyPair, state.value.remoteEphemeralKey)
                }

                token == Token.SE && role == Role.RESPONDER -> mixKey(
                    state.value.localEphemeralKeyPair,
                    state.value.remoteStaticKey
                )

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
            state == null -> null
            rest.isEmpty() -> symmetry.split()
                .let {
                    State(
                        Transport(
                            it.first,
                            it.second,
                            symmetry.handshakeHash.digest
                        ),
                        state.result
                    )
                }

            else ->
                State(
                    state.value.copy(messagePatterns = rest),
                    state.result
                )
        }
    }

    companion object {

        fun initialize(
            cryptography: Cryptography,
            pattern: Pattern,
            role: Role,
            prologue: Data,
            s: Pair<PublicKey, PrivateKey>? = null,
            e: Pair<PublicKey, PrivateKey>? = null,
            rs: PublicKey? = null,
            re: PublicKey? = null,
            trustedStaticKeys: Set<PublicKey> = emptySet()
        ): Handshake? {
            var state = Symmetry.initialize(cryptography, pattern.name).mixHash(prologue)
            if (pattern.preSharedMessagePatterns.isNotEmpty()) {
                for (p in pattern.preSharedMessagePatterns[0]) {
                    if (p == Token.S && role == Role.INITIATOR && s != null) {
                        state = state.mixHash(s.first.data)
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
                        state = state.mixHash(s.first.data)
                    } else if (p == Token.S && role == Role.INITIATOR && rs != null) {
                        state = state.mixHash(rs.data)
                    } else {
                        return null
                    }
                }
            }
            return Handshake(role, state, pattern.messagePatterns, s, e, rs, re, trustedStaticKeys)
        }

        val Noise_XN_25519_ChaChaPoly_SHA256 =
            Pattern(
                "Noise_XN_25519_ChaChaPoly_SHA256",
                listOf(),
                listOf(listOf(Token.E), listOf(Token.E, Token.EE), listOf(Token.S, Token.SE))
            )

        val Noise_NK_25519_ChaChaPoly_SHA256 =
            Pattern(
                "Noise_NK_25519_ChaChaPoly_SHA256",
                listOf(listOf(), listOf(Token.S)),
                listOf(listOf(Token.E, Token.ES), listOf(Token.E, Token.EE))
            )
    }
}
