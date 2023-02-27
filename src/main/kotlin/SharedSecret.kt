package nl.sanderdijkhuis.noise

@JvmInline
value class SharedSecret(val value: ByteArray) {

    val inputKeyMaterial get() = InputKeyMaterial(value)
}
