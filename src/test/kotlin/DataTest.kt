package nl.sanderdijkhuis.noise

import org.junit.jupiter.api.assertDoesNotThrow
import org.junit.jupiter.api.assertThrows
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals

class DataTest {

    @Test
    fun testSize() {
        assertDoesNotThrow { Data(ByteArray(0)) }
        assertDoesNotThrow { Data(ByteArray(Size.MAX_MESSAGE.value)) }
        assertDoesNotThrow { Data(ByteArray(Size.MAX_MESSAGE.value - 1)) }
        assertThrows<IllegalArgumentException> { Data(ByteArray(Size.MAX_MESSAGE.value + 1)) }
    }

    @Test
    fun testHashCode() {
        val data1 = Data(byteArrayOf(0x01))
        val data2 = Data(byteArrayOf(0x01))
        assertEquals(data1.hashCode(), data2.hashCode())
    }

    @Test
    fun testXor() {
        assertThrows<IllegalArgumentException> { Data.empty.xor(Data(byteArrayOf(0x01))) }
    }

    @Test
    fun testEquals() {
        val data1 = Data(byteArrayOf(0x01))
        val data2 = Data(byteArrayOf(0x01))
        val data3 = Data(byteArrayOf(0x02))
        assertEquals(data1, data1)
        assertNotEquals(data1 as Any, object {})
        assertEquals(data1, data2)
        assertNotEquals(data1, data3)
    }
}
