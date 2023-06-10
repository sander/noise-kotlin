package nl.sanderdijkhuis.noise

import nl.sanderdijkhuis.noise.Handshake.Token.*
import nl.sanderdijkhuis.noise.Role.INITIATOR
import nl.sanderdijkhuis.noise.Role.RESPONDER
import nl.sanderdijkhuis.noise.cryptography.*
import nl.sanderdijkhuis.noise.data.Data
import nl.sanderdijkhuis.noise.data.Size
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

    private fun State<Handshake, Data>.run(d: Data = Data.empty, f: (Symmetry) -> Symmetry) =
        copy(value = value.copy(symmetry = f(value.symmetry)), result = result + d)

    private fun State<Handshake, Data>.append(f: (Symmetry) -> State<Symmetry, Data>?) =
        f(value.symmetry)?.let { s -> State(value.copy(symmetry = s.value), result + s.result) }

    fun writeMessage(payload: Payload): State<out MessageType, Data>? =
        messagePatterns.first().fold(State(this, Data.empty) as State<Handshake, Data>?) { state, token ->
            state?.let { s ->
                fun mix(local: Pair<PublicKey, PrivateKey>?, remote: PublicKey?) =
                    local?.let { l -> remote?.let { r -> s.run { it.mixKey(cryptography.agree(l.second, r)) } } }
                when {
                    token == E -> localEphemeralKeyPair?.let { e -> s.run(e.first.data) { it.mixHash(e.first.data) } }
                    token == S -> localStaticKeyPair?.let { p -> s.append { it.encryptAndHash(p.first.plaintext) } }
                    token == EE -> mix(localEphemeralKeyPair, remoteEphemeralKey)
                    token == ES && role == INITIATOR -> mix(localEphemeralKeyPair, remoteStaticKey)
                    token == ES && role == RESPONDER -> mix(localStaticKeyPair, remoteEphemeralKey)
                    token == SE && role == INITIATOR -> mix(localStaticKeyPair, remoteEphemeralKey)
                    token == SE && role == RESPONDER -> mix(localEphemeralKeyPair, remoteStaticKey)
                    token == SS -> mix(localStaticKeyPair, remoteStaticKey)
                    else -> null
                }
            }
        }
            ?.append { it.encryptAndHash(Plaintext(payload.data)) }
            ?.let { s ->
                val rest = messagePatterns.drop(1)
                if (rest.isEmpty()) s.value.symmetry.split().let {
                    State(Transport(it.first, it.second, s.value.symmetry.handshakeHash.digest), s.result)
                }
                else State(s.value.copy(messagePatterns = rest), s.result)
            }

    fun readMessage(data: Data): State<out MessageType, Payload>? =
        messagePatterns.first().fold(State(this, data) as State<Handshake, Data>?) { state, token ->
            state?.let { s ->
                fun mix(f: (Handshake) -> Pair<PublicKey, PrivateKey>?, g: (Handshake) -> PublicKey?) =
                    f(s.value)?.let { l ->
                        g(s.value)?.let { r -> s.run { it.mixKey(cryptography.agree(l.second, r)) } }
                    }

                fun read(size: Size?, f: (Data) -> Handshake?): State<Handshake, Data>? =
                    size?.let { s.result.readFirst(it) }?.let { v -> f(v.first)?.let { s.copy(it, v.second) } }
                when {
                    token == E && s.value.remoteEphemeralKey == null -> read(SharedSecret.SIZE) {
                        s.value.copy(symmetry = s.value.symmetry.mixHash(it), remoteEphemeralKey = PublicKey(it))
                    }

                    token == S && s.value.remoteStaticKey == null -> read(SharedSecret.SIZE + Size(16u)) { r ->
                        s.value.symmetry.decryptAndHash(Ciphertext(r))?.let { ss ->
                            trustedStaticKeys.firstOrNull { it == PublicKey(ss.result.data) }
                                ?.let { s.value.copy(symmetry = ss.value, remoteStaticKey = it) }
                        }
                    }

                    token == EE -> mix({ it.localEphemeralKeyPair }, { it.remoteEphemeralKey })
                    token == ES && role == INITIATOR -> mix({ it.localEphemeralKeyPair }, { it.remoteStaticKey })
                    token == ES && role == RESPONDER -> mix({ it.localStaticKeyPair }, { it.remoteEphemeralKey })
                    token == SE && role == INITIATOR -> mix({ it.localStaticKeyPair }, { it.remoteEphemeralKey })
                    token == SE && role == RESPONDER -> mix({ it.localEphemeralKeyPair }, { it.remoteStaticKey })
                    token == SS -> mix({ it.localStaticKeyPair }, { it.remoteStaticKey })
                    else -> null
                }
            }
        }?.let {
            it.value.symmetry.decryptAndHash(Ciphertext(it.result))?.let { decrypted ->
                State(it.value.copy(symmetry = decrypted.value), Payload(decrypted.result.data))
            }
        }?.let { s ->
            val rest = messagePatterns.drop(1)
            if (rest.isEmpty()) s.value.symmetry.split()
                .let { State(Transport(it.first, it.second, s.value.symmetry.handshakeHash.digest), s.result) }
            else State(s.value.copy(messagePatterns = rest), s.result)
        }

    companion object {

        fun initialize(
            cryptography: Cryptography,
            pattern: Pattern,
            role: Role,
            prologue: Data,
            localStaticKeyPair: Pair<PublicKey, PrivateKey>? = null,
            localEphemeralKeyPair: Pair<PublicKey, PrivateKey>? = null,
            remoteStaticKey: PublicKey? = null,
            trustedStaticKeys: Set<PublicKey> = emptySet()
        ): Handshake? = pattern.preSharedMessagePatterns.foldIndexed(
            Symmetry.initialize(cryptography, pattern.name).mixHash(prologue) as Symmetry?
        ) { index, state, p ->
            p.fold(state) { s, t ->
                when {
                    index == 0 && t == S && role == INITIATOR -> localStaticKeyPair?.let { s?.mixHash(it.first.data) }
                    index == 0 && t == S && role == RESPONDER -> remoteStaticKey?.let { s?.mixHash(it.data) }
                    index == 1 && t == S && role == RESPONDER -> localStaticKeyPair?.let { s?.mixHash(it.first.data) }
                    index == 1 && t == S && role == INITIATOR -> remoteStaticKey?.let { s?.mixHash(it.data) }
                    else -> null
                }
            }
        }?.let {
            Handshake(
                role,
                it,
                pattern.messagePatterns,
                localStaticKeyPair,
                localEphemeralKeyPair,
                remoteStaticKey,
                null,
                trustedStaticKeys
            )
        }

        val Noise_XN_25519_ChaChaPoly_SHA256 =
            Pattern(
                "Noise_XN_25519_ChaChaPoly_SHA256",
                listOf(),
                listOf(listOf(E), listOf(E, EE), listOf(S, SE))
            )

        val Noise_NK_25519_ChaChaPoly_SHA256 =
            Pattern(
                "Noise_NK_25519_ChaChaPoly_SHA256",
                listOf(listOf(), listOf(S)),
                listOf(listOf(E, ES), listOf(E, EE))
            )
    }
}
