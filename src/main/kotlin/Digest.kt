package nl.sanderdijkhuis.noise

@JvmInline
value class Digest(val data: Data) {

    init {
        data.require(SIZE)
    }

    companion object {

        val SIZE = Size(32)
    }
}
