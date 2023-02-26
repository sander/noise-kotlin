package nl.sanderdijkhuis.noise

@JvmInline
value class Digest(val value: ByteArray) {

    init {
        require(value.size == HashConfiguration.hashSize.value)
    }

    fun data() = Data(value)

    fun associatedData() = AssociatedData(value)
}
