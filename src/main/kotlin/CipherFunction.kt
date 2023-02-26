package nl.sanderdijkhuis.noise

/** https://noiseprotocol.org/noise.html#cipher-functions */
sealed interface CipherFunction {

    data class Encrypt(
        val key: CipherKey,
        val nonce: Nonce,
        val associatedData: AssociatedData,
        val plaintext: Plaintext
    ) : CipherFunction

    data class Decrypt(
        val key: CipherKey,
        val nonce: Nonce,
        val associatedData: AssociatedData,
        val ciphertext: Ciphertext
    ) : CipherFunction

    data class Rekey(val key: CipherKey): CipherFunction
}
