package nl.sanderdijkhuis.noise

import nl.sanderdijkhuis.noise.HandshakeState.*
import org.junit.jupiter.api.Test

class HandshakeTest {

    private fun String.toPayload() = Payload(Data(toByteArray()))

    @Test
    fun testHandshake() {
        val aliceStaticKey = JavaCryptography.generateKeyPair()
        val pattern = HandshakePattern.Noise_XN_25519_ChaChaPoly_SHA256
        val prologue = Prologue(Data.empty())
        val alice00 = HandshakeState.initialize(
            JavaCryptography,
            pattern,
            HandshakeState.Role.INITIATOR,
            prologue,
            e = JavaCryptography.generateKeyPair(),
            s = aliceStaticKey
        )
        val bob00 = HandshakeState.initialize(
            JavaCryptography,
            pattern,
            HandshakeState.Role.RESPONDER,
            prologue,
            e = JavaCryptography.generateKeyPair(),
        )

        val string01 = "Hello"
        val string02 = "Hi"
        val string03 = "Bye"

        val alice01 = alice00.writeMessage(string01.toPayload()) as MessageResult.IntermediateHandshakeMessage
        val bob01 = bob00.readMessage(alice01.result) as MessageResult.IntermediateHandshakeMessage
        assert(String(bob01.result.data.value) == string01)

        val bob02 = bob01.state.writeMessage(string02.toPayload()) as MessageResult.IntermediateHandshakeMessage
        val alice02 = alice01.state.readMessage(bob02.result) as MessageResult.IntermediateHandshakeMessage
        assert(String(alice02.result.data.value) == string02)

        val alice03 = alice02.state.writeMessage(string03.toPayload()) as MessageResult.FinalHandshakeMessage
        val bob03 = bob02.state.readMessage(alice03.result) as MessageResult.FinalHandshakeMessage
        assert(String(bob03.result.data.value) == string03)

        println(bob03)
    }
}
