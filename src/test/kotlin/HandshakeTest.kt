package nl.sanderdijkhuis.noise

import org.junit.jupiter.api.Test

class HandshakeTest {

    @Test
    fun testHandshake() {
        val handshake = HandshakeState.initialize(
            JavaCryptography,
            HandshakePattern,
            HandshakeState.Role.INITIATOR,
            Prologue(Data.empty()),
            e = JavaCryptography.generateKeyPair()
        ).writeMessage(Payload(Data.empty()))
        println(handshake)
    }
}
