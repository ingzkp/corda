package net.corda.core.crypto

import net.corda.core.contracts.PrivacySalt
import net.corda.core.crypto.internal.DigestAlgorithmFactory
import net.corda.core.utilities.OpaqueBytes
import org.bouncycastle.crypto.digests.Blake2sDigest
import org.junit.Assert.assertArrayEquals
import org.junit.Before
import org.junit.Test
import java.nio.ByteBuffer
import kotlin.test.assertEquals

class Blake2s256DigestServiceTest {
    class BLAKE2s256DigestAlgorithm : DigestAlgorithm {
        override val algorithm = "BLAKE_TEST"

        override val digestLength = 32

        override fun digest(bytes: ByteArray): ByteArray {
            val blake2s256 = Blake2sDigest(null, digestLength, null, "12345678".toByteArray())
            blake2s256.reset()
            blake2s256.update(bytes, 0, bytes.size)
            val hash = ByteArray(digestLength)
            blake2s256.doFinal(hash, 0)
            return hash
        }

        /**
         * Computes the digest of the [ByteArray] which is resistant to pre-image attacks.
         * Default implementation provides double hashing, but can it be changed to single hashing or something else for better performance.
         */
        override fun preImageResistantDigest(bytes: ByteArray): ByteArray = digest(bytes)

        /**
         * Computes the digest of the [ByteArray] which is resistant to pre-image attacks.
         * Default implementation provides double hashing, but can it be changed to single hashing or something else for better performance.
         */
        override fun nonceDigest(bytes: ByteArray): ByteArray = bytes
    }

    private val service = DigestService("BLAKE_TEST")

    @Before
    fun before() {
        DigestAlgorithmFactory.registerClass(BLAKE2s256DigestAlgorithm::class.java.name)
    }

    @Test(timeout = 300_000)
    fun testCustomNonceHash() {
        val leafBytes = "TEST".toByteArray()
        val privacySalt = PrivacySalt("A".padEnd(32).toByteArray())
        val groupIndex = 0
        val componentIndexInGroup = 0
        /*
         * internal val availableComponentNonces: Map<Int, List<SecureHash>> by lazy {
         *     componentGroups.associate { it.groupIndex to it.components.mapIndexed { internalIndex, internalIt -> digestService.componentHash(internalIt, privacySalt, it.groupIndex, internalIndex) } }
         * }
         */
        val actualLeafNonce = service.componentHash(OpaqueBytes(leafBytes), privacySalt, groupIndex, componentIndexInGroup)
        /*
         * internal val availableComponentHashes: Map<Int, List<SecureHash>> by lazy {
         *     componentGroups.associate { it.groupIndex to it.components.mapIndexed { internalIndex, internalIt ->
         *         digestService.componentHash(availableComponentNonces[it.groupIndex]!![internalIndex], internalIt)
         *     }}
         * }
         */
        val actualLeafHash = service.componentHash(actualLeafNonce, OpaqueBytes(leafBytes))

        /*
         * We have overridden nonce hash to do nothing and just return its input, so that the bug of double hashing the nonce still present
         * in DigestService.componenHash, which is called from WireTransaction.availableComponentNonces, is negated.
         *
         * Note that in this function, not just `computeNonce()` is called, but it is hashed again.
         * this last extra hashing is incorrect, as was confirmed here: https://groups.io/g/corda-dev/message/1285
         *
         * fun componentHash(opaqueBytes: OpaqueBytes, privacySalt: PrivacySalt, componentGroupIndex: Int, internalIndex: Int): SecureHash =
         *         componentHash(computeNonce(privacySalt, componentGroupIndex, internalIndex), opaqueBytes)
         *
         * Not part of this test, but a way to remove this bug properly for custom digests, is to move it to the
         * `SecureHash.nonceHashAs` for the default SHA256 algo implementation. That way, backward compatibility is guaranteed,
         * but new aglo implementations are not burdened with it. Unfortunately, this is not possible now, because it
         * does not receive the leaf bytes as a parameter.
         */
        val nonceInputBytes = (privacySalt.bytes + ByteBuffer.allocate(8).putInt(groupIndex).putInt(componentIndexInGroup).array())
        // Please note that the workaround of having BLAKE2s256DigestAlgorithm.nonceDigest() return its
        // input unchanged solves the bug suboptimally: yes, it does remove the unnecessary double hashing, but
        // it still adds the leafBytes to the hash operation, which makes the input for that operation longer and therefore slower.
        val expectedLeafNonce = service.hash(nonceInputBytes + leafBytes)
        val expectedLeafHash = service.hash(expectedLeafNonce.bytes + leafBytes)

        assertEquals(expectedLeafNonce, actualLeafNonce)
        assertEquals(expectedLeafHash, actualLeafHash)
    }

    @Test(timeout = 300_000)
    fun testBlankHash() {
        assertEquals(
                "BLAKE_TEST:C59F682376D137F3F255E671E207D1F2374EBE504E9314208A52D9F88D69E8C8",
                service.hash(byteArrayOf()).toString()
        )
        assertEquals("C59F682376D137F3F255E671E207D1F2374EBE504E9314208A52D9F88D69E8C8", service.hash(byteArrayOf()).toHexString())
    }

    @Test(timeout = 300_000)
    fun testHashBytes() {
        val hash = service.hash(byteArrayOf(0x64, -0x13, 0x42, 0x3a))
        assertEquals("BLAKE_TEST:9EEA14092257E759ADAA56539A7A88DA1F68F03ABE3D9552A21D4731F4E6ECA0", hash.toString())
        assertEquals("9EEA14092257E759ADAA56539A7A88DA1F68F03ABE3D9552A21D4731F4E6ECA0", hash.toHexString())
    }

    @Test(timeout = 300_000)
    fun testHashString() {
        val hash = service.hash("test")
        assertEquals("BLAKE_TEST:AB76E8F7EEA1968C183D343B756EC812E47D4BC7A3F061F4DDE8948B3E05DAF2", hash.toString())
        assertEquals("AB76E8F7EEA1968C183D343B756EC812E47D4BC7A3F061F4DDE8948B3E05DAF2", hash.toHexString())
    }

    @Test(timeout = 300_000)
    fun testGetAllOnesHash() {
        assertArrayEquals(service.allOnesHash.bytes, ByteArray(32) { 0xFF.toByte() })
    }

    @Test(timeout = 300_000)
    fun testGetZeroHash() {
        assertArrayEquals(service.zeroHash.bytes, ByteArray(32))
    }

    @Test(timeout = 300_000)
    fun `Blake2s256 does not retain state between same-thread invocations`() {
        assertEquals(service.hash("abc"), service.hash("abc"))
    }
}