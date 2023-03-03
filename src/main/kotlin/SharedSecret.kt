package nl.sanderdijkhuis.noise

import nl.sanderdijkhuis.noise.Size.Companion.valueSize

@JvmInline
value class SharedSecret(val value: ByteArray) {

    init {
        require(value.valueSize == SIZE)
    }

    val inputKeyMaterial get() = InputKeyMaterial(value)

    companion object {

        val SIZE = KeyAgreementConfiguration.SIZE
    }
}
