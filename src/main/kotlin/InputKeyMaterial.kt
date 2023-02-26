package nl.sanderdijkhuis.noise

@JvmInline
value class InputKeyMaterial(val value: ByteArray) {

    fun data() = Data(value)

    init {
        require(value.isEmpty() || value.size == DEFAULT_SIZE || value.size == KeyAgreementConfiguration.size.value)
    }

    companion object {

        const val DEFAULT_SIZE = 32
    }
}