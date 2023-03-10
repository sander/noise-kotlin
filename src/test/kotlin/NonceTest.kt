package nl.sanderdijkhuis.noise

import org.junit.jupiter.api.assertThrows
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

class NonceTest {

    @Test
    fun testSize() {
        assertThrows<IllegalArgumentException> { Nonce(ByteArray(Nonce.SIZE.value + 1)) }
    }

    @Test
    fun testIncrement() {
        assertEquals(Nonce.zero.increment()?.toULong(), 1u)
        assertNull(Nonce(ULong.MAX_VALUE).increment())
    }
}
