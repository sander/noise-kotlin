package nl.sanderdijkhuis.noise

import java.nio.ByteBuffer
import java.nio.ByteOrder
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNull

class NonceTest {

    @Test
    fun testSize() {
        assertNull(Nonce.from(ByteArray(Nonce.SIZE.value + 1)))
    }

    @Test
    fun testIncrement() {
        assertEquals(Nonce.zero.increment()?.value, 1u)
        assertNull(Nonce(ULong.MAX_VALUE).increment())
    }

    @Test
    fun testLittleEndian() {
        assertEquals((0uL).toLong(), 0L)
        assertEquals(ULong.MAX_VALUE.toLong(), -1L)
        assertEquals(ULong.MIN_VALUE.toLong(), 0L)
        fun test(x: ULong) = assertContentEquals(
            Nonce(x).bytes,
            ByteBuffer.allocate(Nonce.SIZE.value).order(ByteOrder.LITTLE_ENDIAN).putLong(x.toLong()).array()
        )
        test(1uL)
        test(255uL)
        test(256uL)
        test(ULong.MAX_VALUE)
        assertContentEquals(Nonce(ULong.MAX_VALUE).bytes, Nonce.SIZE.byteArray { (0xff).toByte() })
    }
}
