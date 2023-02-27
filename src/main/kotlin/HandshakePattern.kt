package nl.sanderdijkhuis.noise

import nl.sanderdijkhuis.noise.HandshakeState.Token

data class HandshakePattern(val name: ProtocolName, val messagePatterns: List<List<Token>>) {

    companion object {

        val Noise_XN_25519_ChaChaPoly_SHA256 =
            HandshakePattern(
                ProtocolName("Noise_XN_25519_ChaChaPoly_SHA256".toByteArray()),
                listOf(listOf(Token.E), listOf(Token.E, Token.EE), listOf(Token.S, Token.SE))
            )
    }
}
