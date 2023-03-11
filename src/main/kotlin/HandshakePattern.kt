package nl.sanderdijkhuis.noise

data class HandshakePattern(
    val name: String,
    val preSharedMessagePatterns: List<List<Token>>,
    val messagePatterns: List<List<Token>>
) {

    companion object {

        val Noise_XN_25519_ChaChaPoly_SHA256 =
            HandshakePattern(
                "Noise_XN_25519_ChaChaPoly_SHA256",
                listOf(),
                listOf(listOf(Token.E), listOf(Token.E, Token.EE), listOf(Token.S, Token.SE))
            )

        val Noise_NK_25519_ChaChaPoly_SHA256 =
            HandshakePattern(
                "Noise_NK_25519_ChaChaPoly_SHA256",
                listOf(listOf(), listOf(Token.S)),
                listOf(listOf(Token.E, Token.ES), listOf(Token.E, Token.EE))
            )
    }
}
