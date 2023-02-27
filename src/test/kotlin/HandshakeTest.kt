package nl.sanderdijkhuis.noise

import org.junit.jupiter.api.Test

class HandshakeTest {

    @Test
    fun testHandshake() {
        val prologue = Prologue(Data.empty())
        val alice01 = HandshakeState.initialize(
            JavaCryptography,
            HandshakePattern.Noise_XN_25519_ChaChaPoly_SHA256,
            HandshakeState.Role.INITIATOR,
            prologue,
            e = JavaCryptography.generateKeyPair()
        ).writeMessage(Payload(Data.empty())) as HandshakeState.MessageResult.IntermediateHandshakeMessage
        val bob01 = HandshakeState.initialize(
            JavaCryptography,
            HandshakePattern.Noise_XN_25519_ChaChaPoly_SHA256,
            HandshakeState.Role.RESPONDER,
            prologue,
            e = JavaCryptography.generateKeyPair()
        ).readMessage(alice01.message) as HandshakeState.MessageResult.IntermediateHandshakeMessage
        println(bob01)
    }
}
