package nl.sanderdijkhuis.noise

import org.junit.jupiter.api.Test

class HandshakeTest {

    private fun String.toPayload() = Payload(Data(toByteArray()))

    @Test
    fun testHandshakeXN() {
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
        )!!
        val bob00 = HandshakeState.initialize(
            JavaCryptography,
            pattern,
            HandshakeState.Role.RESPONDER,
            prologue,
            e = JavaCryptography.generateKeyPair(),
        )!!

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

    @Test
    fun testHandshakeNK() {
        val bobStaticKey = JavaCryptography.generateKeyPair()
        val pattern = HandshakePattern.Noise_NK_25519_ChaChaPoly_SHA256
        val prologue = Prologue(Data.empty())
        val alice00 = HandshakeState.initialize(
            JavaCryptography,
            pattern,
            HandshakeState.Role.INITIATOR,
            prologue,
            e = JavaCryptography.generateKeyPair(),
            rs = bobStaticKey.public
        )!!
        val bob00 = HandshakeState.initialize(
            JavaCryptography,
            pattern,
            HandshakeState.Role.RESPONDER,
            prologue,
            e = JavaCryptography.generateKeyPair(),
            s = bobStaticKey
        )!!

        val string01 = "Hello"
        val string02 = "Hi"
        val string03 = "Another message"

        val alice01 = alice00.writeMessage(string01.toPayload()) as MessageResult.IntermediateHandshakeMessage
        val bob01 = bob00.readMessage(alice01.result) as MessageResult.IntermediateHandshakeMessage
        assert(String(bob01.result.data.value) == string01)

        val bob02 = bob01.state.writeMessage(string02.toPayload()) as MessageResult.FinalHandshakeMessage
        val alice02 = alice01.state.readMessage(bob02.result) as MessageResult.FinalHandshakeMessage
        assert(String(alice02.result.data.value) == string02)

        val bob03 = bob02.responderCipherState.encryptWithAssociatedData(AssociatedData.empty(), string03.toPayload().plainText)
        val alice03 = alice02.responderCipherState.decryptWithAssociatedData(AssociatedData.empty(), bob03)!!
        assert(String(alice03.value) == string03)

        println(alice02)
    }
}
