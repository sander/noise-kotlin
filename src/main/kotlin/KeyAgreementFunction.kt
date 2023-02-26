package nl.sanderdijkhuis.noise

/** https://noiseprotocol.org/noise.html#dh-functions */
sealed interface KeyAgreementFunction {

    object GenerateKeyPair : KeyAgreementFunction

    data class Agree(val privateKey: PrivateKey, val publicKey: PublicKey) : KeyAgreementFunction
}
