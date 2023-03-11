package nl.sanderdijkhuis.noise

@JvmInline
value class CipherKey(val data: Data) {

    init {
        data.require(SIZE)
    }

    companion object {

        val SIZE = Size(32)
    }
}