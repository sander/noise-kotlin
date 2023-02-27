package nl.sanderdijkhuis.noise

import nl.sanderdijkhuis.noise.HandshakeState.ReadMessageResult
import nl.sanderdijkhuis.noise.HandshakeState.WriteMessageResult
import org.junit.jupiter.api.Test

class HandshakeTest {

    private fun String.toPayload() = Payload(Data(toByteArray()))

    @Test
    fun testHandshake() {
        val bobStaticKey = JavaCryptography.generateKeyPair()
        val pattern = HandshakePattern.Noise_XN_25519_ChaChaPoly_SHA256
        val prologue = Prologue(Data.empty())
        val string01 = "Hello"
        val alice01 = HandshakeState.initialize(
            JavaCryptography,
            pattern,
            HandshakeState.Role.INITIATOR,
            prologue,
            e = JavaCryptography.generateKeyPair(),
            rs = bobStaticKey.public
        ).writeMessage(string01.toPayload()) as WriteMessageResult.IntermediateHandshakeMessage
        val bob01 = HandshakeState.initialize(
            JavaCryptography,
            pattern,
            HandshakeState.Role.RESPONDER,
            prologue,
            e = JavaCryptography.generateKeyPair(),
            s = bobStaticKey
        ).readMessage(alice01.message) as ReadMessageResult.IntermediateHandshakeMessage
        assert(String(bob01.payload.data.value) == string01)
        val string02 = "Hi"
        val bob02 = bob01.state.writeMessage(string02.toPayload()) as WriteMessageResult.IntermediateHandshakeMessage
        val alice02 = alice01.state.readMessage(bob02.message) as ReadMessageResult.IntermediateHandshakeMessage
        assert(String(alice02.payload.data.value) == string02)
        println(alice02)
    }
}
