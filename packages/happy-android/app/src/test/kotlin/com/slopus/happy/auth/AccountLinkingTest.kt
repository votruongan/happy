package com.slopus.happy.auth

import com.slopus.happy.crypto.AccountEncryption
import com.slopus.happy.crypto.AccountLink
import com.slopus.happy.crypto.Base64Variant
import com.slopus.happy.crypto.SecureRandomSource
import com.slopus.happy.crypto.Sodium
import com.slopus.happy.crypto.decodeBase64
import com.slopus.happy.crypto.decryptBox
import com.slopus.happy.crypto.encodeBase64
import com.slopus.happy.net.HappyHttp
import com.slopus.happy.net.HttpStatusException
import com.slopus.happy.testing.FakeHappyServer
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import okhttp3.OkHttpClient
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test
import kotlin.time.Duration.Companion.milliseconds

/**
 * Account link (restore/index.tsx with authQRStart/authQRWait, and
 * useConnectAccount's approval) and terminal approval (authApprove.ts)
 * against the in-memory server's authRoutes.ts contract.
 */
class AccountLinkingTest {
    private lateinit var server: FakeHappyServer
    private lateinit var api: AuthApi

    @Before
    fun setUp() {
        server = FakeHappyServer().start()
        api = AuthApi(HappyHttp(OkHttpClient(), serverUrl = { server.url }, clientId = "android/test"))
    }

    @After
    fun tearDown() = server.close()

    private val credentials get() = AuthCredentials(token = server.token, secret = encodeBase64(server.secret, Base64Variant.Url))

    @Test
    fun aNewPhoneGetsTheSecretTheOtherPhoneApproves() = runBlocking {
        val newPhone = AccountLinkRequest(api)
        assertTrue(newPhone.url.startsWith("happy:///account?"))
        newPhone.start()
        val publicKey = encodeBase64(newPhone.keyPair.publicKey)
        assertTrue(publicKey in server.accountRequests)

        val waiting = async { newPhone.awaitApproval(pollInterval = 20.milliseconds) }
        // The phone that has the account scans the code.
        approveAccountLink(api, credentials, newPhone.url)

        val linked = withTimeout(5_000) { waiting.await() }!!
        assertEquals(server.token, linked.token)
        assertArrayEquals(server.secret, linked.secret)

        val approval = server.requestsTo("/v1/auth/account/response").single()
        assertEquals("Bearer ${server.token}", approval.headers["Authorization"])
        assertEquals("android/test", approval.headers["X-Happy-Client"])
        // Every poll carries the client header too, and the same key.
        server.requestsTo("/v1/auth/account/request").forEach {
            assertEquals("android/test", it.headers["X-Happy-Client"])
            assertEquals("""{"publicKey":"$publicKey"}""", it.body!!.utf8())
        }
    }

    @Test
    fun anApprovalSealedToAnotherKeyIsNull() = runBlocking {
        val newPhone = AccountLinkRequest(api)
        newPhone.start()
        val stranger = AccountLink.generateKeyPair()
        server.approveAccountRequest(newPhone.keyPair.publicKey, AccountLink.sealSecret(server.secret, stranger.publicKey))
        assertNull(newPhone.awaitApproval(pollInterval = 10.milliseconds))
    }

    @Test
    fun aFailedPollEndsTheWait() = runBlocking {
        val newPhone = AccountLinkRequest(api)
        server.close()
        try {
            newPhone.awaitApproval(pollInterval = 10.milliseconds)
            fail("expected the poll to fail")
        } catch (_: java.io.IOException) {
        }
    }

    @Test
    fun approvingAnythingButAnAccountLinkIsRefused() = runBlocking {
        for (url in listOf("happy://terminal?abc", "https://happy.engineering", "")) {
            try {
                approveAccountLink(api, credentials, url)
                fail("accepted $url")
            } catch (_: InvalidLinkException) {
            }
        }
        assertTrue(server.requestsTo("/v1/auth/account/response").isEmpty())
    }

    @Test
    fun approvingAnUnknownRequestFails() = runBlocking {
        val url = AccountLink.linkUrl(AccountLink.generateKeyPair().publicKey)
        try {
            approveAccountLink(api, credentials, url)
            fail("expected 404")
        } catch (e: HttpStatusException) {
            assertEquals(404, e.status)
        }
    }

    private class Terminal(val keyPair: Sodium.KeyPair, val pairingSecret: ByteArray, val v3Url: String, val legacyUrl: String)

    private fun terminal(supportsV2: Boolean): Terminal {
        val keyPair = Sodium.boxKeypair()
        val pairingSecret = SecureRandomSource.nextBytes(32)
        server.addTerminalRequest(keyPair.publicKey, supportsV2)
        val key = encodeBase64(keyPair.publicKey, Base64Variant.Url)
        return Terminal(
            keyPair,
            pairingSecret,
            v3Url = "${TERMINAL_PAIRING_URL_PREFIX}key=$key&s=${encodeBase64(pairingSecret, Base64Variant.Url)}",
            legacyUrl = LEGACY_TERMINAL_URL_PREFIX + key,
        )
    }

    private fun answerFor(terminal: Terminal): ByteArray? =
        server.terminalRequests.getValue(encodeBase64(terminal.keyPair.publicKey)).response
            ?.let { decryptBox(decodeBase64(it), terminal.keyPair.secretKey) }

    private val contentPublicKey get() = AccountEncryption.create(server.secret).contentPublicKey

    @Test
    fun aV3TerminalGetsTheContentKeyAndItsPairingSecret() = runBlocking {
        val terminal = terminal(supportsV2 = true)
        approveTerminal(api, credentials, server.encryption, terminal.v3Url)
        val answer = answerFor(terminal)!!
        assertEquals(65, answer.size)
        assertEquals(3, answer[0].toInt())
        assertArrayEquals(contentPublicKey, answer.copyOfRange(1, 33))
        assertArrayEquals(terminal.pairingSecret, answer.copyOfRange(33, 65))

        val status = server.requestsTo("/v1/auth/request/status").single()
        assertEquals(encodeBase64(terminal.keyPair.publicKey), status.url.queryParameter("publicKey"))
        val post = server.requestsTo("/v1/auth/response").single()
        assertEquals("Bearer ${server.token}", post.headers["Authorization"])
    }

    @Test
    fun anOlderTerminalGetsTheContentKeyNotTheSecret() = runBlocking {
        val terminal = terminal(supportsV2 = true)
        approveTerminal(api, credentials, server.encryption, terminal.legacyUrl)
        val answer = answerFor(terminal)!!
        assertEquals(33, answer.size)
        assertEquals(0, answer[0].toInt())
        assertArrayEquals(contentPublicKey, answer.copyOfRange(1, 33))
    }

    @Test
    fun aTerminalThatSaysItIsV1NeverGetsTheSecret() = runBlocking {
        // supportsV2 comes from whoever made the request, so it picks nothing.
        val v3 = terminal(supportsV2 = false)
        approveTerminal(api, credentials, server.encryption, v3.v3Url)
        assertArrayEquals(byteArrayOf(3) + contentPublicKey + v3.pairingSecret, answerFor(v3))

        val legacy = terminal(supportsV2 = false)
        approveTerminal(api, credentials, server.encryption, legacy.legacyUrl)
        assertArrayEquals(byteArrayOf(0) + contentPublicKey, answerFor(legacy))

        for (answer in listOf(answerFor(v3)!!, answerFor(legacy)!!)) {
            assertNotEquals(32, answer.size)
            assertFalse(answer.toList().windowed(32).any { it.toByteArray().contentEquals(server.secret) })
        }
    }

    @Test
    fun anAnsweredTerminalIsAWarningNotSuccess() = runBlocking {
        val terminal = terminal(supportsV2 = true)
        approveTerminal(api, credentials, server.encryption, terminal.v3Url)
        val first = server.terminalRequests.getValue(encodeBase64(terminal.keyPair.publicKey)).response
        try {
            approveTerminal(api, credentials, server.encryption, terminal.v3Url)
            fail("an answered request counted as connected")
        } catch (_: TerminalAlreadyAnsweredException) {
        }
        assertEquals(first, server.terminalRequests.getValue(encodeBase64(terminal.keyPair.publicKey)).response)
        assertEquals(1, server.requestsTo("/v1/auth/response").size)
    }

    @Test
    fun anAnswerThatLosesTheRaceIsAWarning() = runBlocking {
        val terminal = terminal(supportsV2 = true)
        val request = server.terminalRequests.getValue(encodeBase64(terminal.keyPair.publicKey))
        request.response = encodeBase64(byteArrayOf(1, 2, 3))
        request.answeredUnseen = true
        try {
            approveTerminal(api, credentials, server.encryption, terminal.v3Url)
            fail("a 409 counted as connected")
        } catch (_: TerminalAlreadyAnsweredException) {
        }
        assertEquals(1, server.requestsTo("/v1/auth/response").size)
        assertEquals(encodeBase64(byteArrayOf(1, 2, 3)), request.response)
    }

    @Test
    fun anUnknownTerminalIsAnError() = runBlocking {
        val unknown = LEGACY_TERMINAL_URL_PREFIX + encodeBase64(Sodium.boxKeypair().publicKey, Base64Variant.Url)
        try {
            approveTerminal(api, credentials, server.encryption, unknown)
            fail("an unknown request counted as connected")
        } catch (_: TerminalAlreadyAnsweredException) {
            fail("an unknown request is not a warning")
        } catch (_: IllegalStateException) {
        }
        assertTrue(server.requestsTo("/v1/auth/response").isEmpty())
    }

    @Test
    fun aTerminalLinkMustBeValid() = runBlocking {
        val terminal = terminal(supportsV2 = true)
        val key = encodeBase64(terminal.keyPair.publicKey, Base64Variant.Url)
        val short = encodeBase64(ByteArray(31), Base64Variant.Url)
        for (url in listOf(
            AccountLink.linkUrl(terminal.keyPair.publicKey),
            "${TERMINAL_PAIRING_URL_PREFIX}key=$key",
            "${TERMINAL_PAIRING_URL_PREFIX}key=$key&s=$short",
            LEGACY_TERMINAL_URL_PREFIX + short,
            "happy://terminal?abc",
            "",
        )) {
            try {
                approveTerminal(api, credentials, server.encryption, url)
                fail("accepted $url")
            } catch (_: InvalidLinkException) {
            }
        }
        assertTrue(server.requestsTo("/v1/auth/request/status").isEmpty())
    }
}
