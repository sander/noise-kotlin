package nl.sanderdijkhuis.noise

@JvmInline
value class InputKeyMaterial(val data: Data) {

    init {
        require(data.isEmpty || data.size == DEFAULT_SIZE || data.size == SharedSecret.SIZE)
    }

    companion object {

        val DEFAULT_SIZE = Size(32)
    }
}