package nl.sanderdijkhuis.noise

@JvmInline
value class SharedSecret(val data: Data) {

    init {
        require(data.size == SIZE)
    }

    val inputKeyMaterial get() = InputKeyMaterial(data)

    companion object {

        val SIZE = Size(32)
    }
}
