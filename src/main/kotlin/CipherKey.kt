package nl.sanderdijkhuis.noise

@JvmInline
value class CipherKey(val data: Data) {

    init {
        require(data.size == SIZE)
    }

    companion object {

        val SIZE = Size(32)
    }
}