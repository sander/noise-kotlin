package nl.sanderdijkhuis.noise

import nl.sanderdijkhuis.noise.cryptography.AssociatedData
import nl.sanderdijkhuis.noise.cryptography.Plaintext
import nl.sanderdijkhuis.noise.data.Data
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
            localEphemeralKeyPair = JavaCryptography.generateKeyPair(),
            localStaticKeyPair = aliceStaticKey
        )!!
        val bob00 = Handshake.initialize(
            JavaCryptography,
            pattern,
            Role.RESPONDER,
            prologue,
            localEphemeralKeyPair = JavaCryptography.generateKeyPair(),
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
    fun testHandshakeNK() {
        val bobStaticKey = JavaCryptography.generateKeyPair()
        val pattern = Handshake.Noise_NK_25519_ChaChaPoly_SHA256
        val prologue = Data.empty
        val alice00 = Handshake.initialize(
            JavaCryptography,
            pattern,
            Role.INITIATOR,
            prologue,
            localEphemeralKeyPair = JavaCryptography.generateKeyPair(),
            remoteStaticKey = bobStaticKey.first,
        )!!
        val bob00 = Handshake.initialize(
            JavaCryptography,
            pattern,
            Role.RESPONDER,
            prologue,
            localEphemeralKeyPair = JavaCryptography.generateKeyPair(),
            localStaticKeyPair = bobStaticKey
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

        val bob03 =
            bob02.state<Transport>()!!.responderCipherState.encrypt(
                AssociatedData(Data.empty),
                Plaintext(string03.toPayload().data)
            )
        val alice03 =
            alice02.state<Transport>()!!.responderCipherState.decrypt(AssociatedData(Data.empty), bob03.result)!!
        assert(String(alice03.result.data.value) == string03)

        println(alice02)
    }

    /** https://github.com/sander/noise-kotlin/discussions/15 */
    @Test
    fun testFinalHandshakeHash() {
        val aliceStaticKey = JavaCryptography.generateKeyPair()
        val alice00 = Handshake.initialize(
            JavaCryptography,
            Handshake.Noise_XN_25519_ChaChaPoly_SHA256,
            Role.INITIATOR,
            Data.empty,
            localEphemeralKeyPair = JavaCryptography.generateKeyPair(),
            localStaticKeyPair = aliceStaticKey
        )!!
        val bob00 = Handshake.initialize(
            JavaCryptography,
            Handshake.Noise_XN_25519_ChaChaPoly_SHA256,
            Role.RESPONDER,
            Data.empty,
            localEphemeralKeyPair = JavaCryptography.generateKeyPair(),
            trustedStaticKeys = setOf(aliceStaticKey.first)
        )!!
        val alice01 = alice00.writeMessage("hello".toPayload())!!
        val bob01 = bob00.readMessage(alice01.result)!!
        val bob02 = bob01.state<Handshake>()?.writeMessage("hi".toPayload())!!
        val alice02 = alice01.state<Handshake>()?.readMessage(bob02.result)!!
        val alice03 = alice02.state<Handshake>()?.writeMessage("bye".toPayload())!!
        val bob03 = bob02.state<Handshake>()?.readMessage(alice03.result)!!
        assert((alice03.value as Transport).handshakeHash == (bob03.value as Transport).handshakeHash)
    }
}
