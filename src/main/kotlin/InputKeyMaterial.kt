package nl.sanderdijkhuis.noise

import nl.sanderdijkhuis.noise.Size.Companion.valueSize

@JvmInline
value class InputKeyMaterial(val value: ByteArray) {

    val data get() = Data(value)

    init {
        require(value.isEmpty() || value.valueSize == DEFAULT_SIZE || value.valueSize == KeyAgreementConfiguration.SIZE)
    }

    companion object {

        val DEFAULT_SIZE = Size(32)
    }
}