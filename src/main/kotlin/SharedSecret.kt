package nl.sanderdijkhuis.noise

@JvmInline
value class SharedSecret(val data: Data) {

    init {
        data.require(SIZE)
    }

    val inputKeyMaterial get() = InputKeyMaterial(data)

    companion object {

        val SIZE = Size(32)
    }
}
