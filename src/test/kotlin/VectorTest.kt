@file:UseSerializers(VectorTest.DataSerializer::class)

package nl.sanderdijkhuis.noise

import kotlinx.serialization.*
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.Json
import nl.sanderdijkhuis.noise.Handshake.Companion.Noise_NK_25519_ChaChaPoly_SHA256
import nl.sanderdijkhuis.noise.Handshake.Companion.Noise_XN_25519_ChaChaPoly_SHA256
import nl.sanderdijkhuis.noise.JavaCryptography.public
import nl.sanderdijkhuis.noise.cryptography.PrivateKey
import nl.sanderdijkhuis.noise.cryptography.PublicKey
import nl.sanderdijkhuis.noise.data.Data
import kotlin.test.Test
import kotlin.test.assertEquals

class VectorTest {

    @Serializable
    data class Message(
        val payload: Data,
        val ciphertext: Data
    )

    @Serializable
    data class Vector(
        @SerialName("protocol_name") val protocolName: String,
        @SerialName("init_prologue") val initPrologue: Data,
        @SerialName("init_psks") val initPsks: List<Data>,
        @SerialName("init_static") val initStatic: Data? = null,
        @SerialName("init_ephemeral") val initEphemeral: Data? = null,
        @SerialName("init_remote_static") val initRemoteStatic: Data? = null,
        @SerialName("resp_prologue") val respPrologue: Data,
        @SerialName("resp_psks") val respPsks: List<Data>,
        @SerialName("resp_static") val respStatic: Data? = null,
        @SerialName("resp_ephemeral") val respEphemeral: Data? = null,
        @SerialName("resp_remote_static") val respRemoteStatic: Data? = null,
        val messages: List<Message>
    )

    @Serializable
    data class VectorFile(val vectors: List<Vector>)

    @Test
    fun testVectors() {
        val string = javaClass.getResource("/vectors/snow.txt")?.readText()!!
        val file = Json.decodeFromString<VectorFile>(string)

        fun Data.keyPair() = PrivateKey(value).let { Pair(it.public(), it) }
        fun Data.public() = PublicKey(this)
        fun Data.payload() = Payload(this)

        listOf(Noise_XN_25519_ChaChaPoly_SHA256, Noise_NK_25519_ChaChaPoly_SHA256).forEach { protocol ->
            val vector = file.vectors.find { it.protocolName == protocol.name }!!
            val initiator = Handshake.initialize(
                JavaCryptography,
                protocol,
                Role.INITIATOR,
                vector.initPrologue,
                vector.initStatic?.keyPair(),
                vector.initEphemeral?.keyPair(),
                vector.initRemoteStatic?.public()
            )!!
            val responder = Handshake.initialize(
                JavaCryptography,
                protocol,
                Role.RESPONDER,
                vector.respPrologue,
                vector.respStatic?.keyPair(),
                vector.respEphemeral?.keyPair(),
                vector.respRemoteStatic?.public()
            )!!
            val m1 = initiator.writeMessage(vector.messages.first().payload.payload())!!
            assertEquals(m1.result, vector.messages.first().ciphertext)
            val m2 = responder.readMessage(m1.result)!!
            val m3 = m2.state<Handshake>()?.writeMessage(vector.messages[1].payload.payload())!!
            assertEquals(m3.result, vector.messages[1].ciphertext)
        }
    }

    object DataSerializer : KSerializer<Data> {

        override val descriptor: SerialDescriptor
            get() = PrimitiveSerialDescriptor("Data", PrimitiveKind.STRING)

        override fun deserialize(decoder: Decoder): Data =
            Data(decoder.decodeString().chunked(2).map { it.toInt(16).toByte() }.toByteArray())

        override fun serialize(encoder: Encoder, value: Data) =
            encoder.encodeString(value.value.joinToString(separator = "") { "%02x".format(it) })
    }
}
