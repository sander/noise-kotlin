package nl.sanderdijkhuis.noise

import nl.sanderdijkhuis.noise.Size.Companion.valueSize

@JvmInline
value class Nonce(val value: ULong) {

    val bytes: ByteArray get() = SIZE.byteArray { (value shr (it * 8)).toByte() }

    fun increment(): Nonce? = if (value == ULong.MAX_VALUE) null else Nonce(value + 1uL)

    companion object {

        val SIZE = Size(8)

        val zero get() = Nonce(0uL)

        fun from(byteArray: ByteArray): Nonce? =
            if (byteArray.valueSize > SIZE) null
            else Nonce(byteArray.mapIndexed { i, b -> (i * b).toULong() }.sum())
    }
}
