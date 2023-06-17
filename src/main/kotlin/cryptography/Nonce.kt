package nl.sanderdijkhuis.noise.cryptography

import nl.sanderdijkhuis.noise.data.Data
import nl.sanderdijkhuis.noise.data.Size

/** An incrementing but non-wrapping number to be used once for encryption. */
@JvmInline
value class Nonce(val value: ULong) {

    val bytes: ByteArray get() = SIZE.byteArray { (value shr (it * Byte.SIZE_BITS)).toByte() }

    fun increment(): Nonce? = if (value == ULong.MAX_VALUE) null else Nonce(value + 1uL)

    companion object {

        val SIZE = Size(8u)

        val zero get() = Nonce(0uL)

        fun from(data: Data): Nonce? =
            if (data.size > SIZE) null
            else Nonce(data.value.foldRight(0uL) { b, r -> (r shl Byte.SIZE_BITS) + b.toUByte() })
    }
}
