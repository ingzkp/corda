package net.corda.node.services.transactions

import net.corda.core.crypto.DigitalSignature
import net.corda.core.crypto.NullKeys
import net.corda.core.crypto.SecureHash
import net.corda.core.crypto.sha256
import net.corda.core.flows.NotarisationRequestSignature
import net.corda.core.flows.NotaryError
import net.corda.core.identity.CordaX500Name
import net.corda.core.internal.notary.UniquenessProvider
import net.corda.node.services.schema.NodeSchemaService
import net.corda.nodeapi.internal.persistence.CordaPersistence
import net.corda.nodeapi.internal.persistence.DatabaseConfig
import net.corda.testing.core.SerializationEnvironmentRule
import net.corda.testing.core.TestIdentity
import net.corda.testing.core.generateStateRef
import net.corda.testing.internal.LogHelper
import net.corda.testing.internal.TestingNamedCacheFactory
import net.corda.testing.internal.configureDatabase
import net.corda.testing.node.MockServices.Companion.makeTestDataSourceProperties
import org.junit.After
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import java.time.Clock
import kotlin.test.assertEquals

class PersistentUniquenessProviderTests {
    @Rule
    @JvmField
    val testSerialization = SerializationEnvironmentRule(inheritable = true)
    private val identity = TestIdentity(CordaX500Name("MegaCorp", "London", "GB")).party
    private val txID = SecureHash.randomSHA256()
    private val requestSignature = NotarisationRequestSignature(DigitalSignature.WithKey(NullKeys.NullPublicKey, ByteArray(32)), 0)

    private lateinit var database: CordaPersistence

    @Before
    fun setUp() {
        LogHelper.setLevel(PersistentUniquenessProvider::class)
        database = configureDatabase(makeTestDataSourceProperties(), DatabaseConfig(runMigration = true), { null }, { null }, NodeSchemaService(extraSchemas = setOf(NodeNotarySchemaV1)))
    }

    @After
    fun tearDown() {
        database.close()
        LogHelper.reset(PersistentUniquenessProvider::class)
    }

    @Test
    fun `should successfully commit a transaction with unused inputs`() {
        val provider = PersistentUniquenessProvider(Clock.systemUTC(), database, TestingNamedCacheFactory())
        val inputState = generateStateRef()

        val result = provider.commit(listOf(inputState), txID, identity, requestSignature).get()
        assertEquals(UniquenessProvider.Result.Success, result)
    }

    @Test
    fun `should report a conflict for a transaction with previously used inputs`() {
        val provider = PersistentUniquenessProvider(Clock.systemUTC(), database, TestingNamedCacheFactory())
        val inputState = generateStateRef()

        val inputs = listOf(inputState)
        val firstTxId = txID
        val result = provider.commit(inputs, firstTxId, identity, requestSignature).get()
        assertEquals(UniquenessProvider.Result.Success, result)

        val secondTxId = SecureHash.randomSHA256()

        val response: UniquenessProvider.Result = provider.commit(inputs, secondTxId, identity, requestSignature).get()
        val error = (response as UniquenessProvider.Result.Failure).error as NotaryError.Conflict

        val conflictCause = error.consumedStates[inputState]!!
        assertEquals(conflictCause.hashOfTransactionId, firstTxId.sha256())
    }
}
