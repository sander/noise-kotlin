package nl.sanderdijkhuis.noise

@JvmInline
value class SharedSecret(val value: ByteArray) {

    init {
        require(value.size == SIZE)
    }

    val inputKeyMaterial get() = InputKeyMaterial(value)

    companion object {

        const val SIZE = 32
    }
}
