package nl.sanderdijkhuis.noise

import org.junit.jupiter.api.Test

class HandshakeTest {

    private fun String.toPayload() = Payload(Data(toByteArray()))

    @Test
    fun testHandshakeXN() {
        val aliceStaticKey = JavaCryptography.generateKeyPair()
        val pattern = Handshake.Noise_XN_25519_ChaChaPoly_SHA256
        val prologue = Data.empty
        val alice00 = Handshake.initialize(
            JavaCryptography,
            pattern,
            Role.INITIATOR,
            prologue,
            e = JavaCryptography.generateKeyPair(),
            s = aliceStaticKey
        )!!
        val bob00 = Handshake.initialize(
            JavaCryptography,
            pattern,
            Role.RESPONDER,
            prologue,
            e = JavaCryptography.generateKeyPair(),
            trustedStaticKeys = setOf(aliceStaticKey.first)
        )!!

        val string01 = "Hello"
        val string02 = "Hi"
        val string03 = "Bye"

        val alice01 = alice00.writeMessage(string01.toPayload())!!
        val bob01 = bob00.readMessage(alice01.result)!!
        assert(String(bob01.result.data.value) == string01)

        val bob02 = bob01.state<Handshake>()?.writeMessage(string02.toPayload())!!
        val alice02 = alice01.state<Handshake>()?.readMessage(bob02.result)!!
        assert(String(alice02.result.data.value) == string02)

        val alice03 = alice02.state<Handshake>()?.writeMessage(string03.toPayload())!!
        val bob03 = bob02.state<Handshake>()?.readMessage(alice03.result)!!
        assert(String(bob03.result.data.value) == string03)

        println(bob03)
    }

    @Test
    @Suppress("UNCHECKED_CAST")
    fun testHandshakeNK() {
        val bobStaticKey = JavaCryptography.generateKeyPair()
        val pattern = Handshake.Noise_NK_25519_ChaChaPoly_SHA256
        val prologue = Data.empty
        val alice00 = Handshake.initialize(
            JavaCryptography,
            pattern,
            Role.INITIATOR,
            prologue,
            e = JavaCryptography.generateKeyPair(),
            rs = bobStaticKey.first,
        )!!
        val bob00 = Handshake.initialize(
            JavaCryptography,
            pattern,
            Role.RESPONDER,
            prologue,
            e = JavaCryptography.generateKeyPair(),
            s = bobStaticKey
        )!!

        val string01 = "Hello"
        val string02 = "Hi"
        val string03 = "Another message"

        val alice01 = alice00.writeMessage(string01.toPayload())!!
        val bob01 = bob00.readMessage(alice01.result)!!
        assert(String(bob01.result.data.value) == string01)

        val bob02 = bob01.state<Handshake>()?.writeMessage(string02.toPayload())!!
        val alice02 = alice01.state<Handshake>()?.readMessage(bob02.result)!!
        assert(String(alice02.result.data.value) == string02)

        val bob03 = bob02.state<Transport>()!!.responderCipherState.encrypt(Data.empty, string03.toPayload().plainText)
        val alice03 = alice02.state<Transport>()!!.responderCipherState.decrypt(Data.empty, bob03.result)!!
        assert(String(alice03.result.data.value) == string03)

        println(alice02)
    }
}
