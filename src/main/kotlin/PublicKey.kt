package nl.sanderdijkhuis.noise

data class PublicKey(val value: ByteArray) {

    val data get() = Data(value)

    val plaintext get() = Plaintext(value)

    override fun equals(other: Any?) =
        this === other || ((other as? PublicKey)?.let { value.contentEquals(it.value) } ?: false)

    override fun hashCode() = value.contentHashCode()
}
