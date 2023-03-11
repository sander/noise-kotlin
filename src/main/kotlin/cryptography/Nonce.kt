package nl.sanderdijkhuis.noise.cryptography

import nl.sanderdijkhuis.noise.data.Data
import nl.sanderdijkhuis.noise.data.Size

@JvmInline
value class Nonce(val value: ULong) {

    val bytes: ByteArray get() = SIZE.byteArray { (value shr (it * 8)).toByte() }

    fun increment(): Nonce? = if (value == ULong.MAX_VALUE) null else Nonce(value + 1uL)

    companion object {

        val SIZE = Size(8u)

        val zero get() = Nonce(0uL)

        fun from(data: Data): Nonce? =
            if (data.size > SIZE) null
            else Nonce(data.value.mapIndexed { i, b -> (i * b).toULong() }.sum())
    }
}
