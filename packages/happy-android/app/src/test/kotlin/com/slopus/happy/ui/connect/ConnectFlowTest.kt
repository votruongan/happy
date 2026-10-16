package com.slopus.happy.ui.connect

import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.test.junit4.v2.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performTextInput
import androidx.compose.ui.test.performClick
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.slopus.happy.auth.TerminalAlreadyAnsweredException
import com.slopus.happy.auth.isTerminalLink
import com.slopus.happy.crypto.Base64Variant
import com.slopus.happy.crypto.encodeBase64
import com.slopus.happy.ui.PHONE
import com.slopus.happy.ui.components.PromptTags
import com.slopus.happy.ui.setHappyContent
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.launch
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.annotation.Config
import java.io.IOException
import java.util.concurrent.CopyOnWriteArrayList

/**
 * The connect flows (useConnectTerminal.ts, useConnectAccount.ts) with a
 * fake scanner: what is approved, what is ignored, what the person is asked
 * first, and what they see.
 */
@RunWith(AndroidJUnit4::class)
@Config(qualifiers = PHONE)
class ConnectFlowTest {
    @get:Rule
    val rule = createComposeRule()

    private val key = encodeBase64(ByteArray(32) { 7 }, Base64Variant.Url)
    private val secret = encodeBase64(ByteArray(32) { 8 }, Base64Variant.Url)
    private val terminalUrl = "happy://pair/terminal?key=$key&s=$secret"
    private val legacyTerminalUrl = "happy://terminal?$key"
    private val accountUrl = "happy:///account?abc"

    private class FakeScanner : QrScanner {
        val results = ArrayDeque<ScanResult>()
        var scans = 0
        override suspend fun scan(): ScanResult {
            scans++
            return results.removeFirst()
        }
    }

    private val scanner = FakeScanner()
    private val approved = CopyOnWriteArrayList<String>()
    private var failWith: Exception? = null
    private var successes = 0
    private var errors = 0
    private lateinit var flow: ConnectFlow

    private lateinit var scope: CoroutineScope

    private fun setTerminal(withOnError: Boolean = false) {
        rule.setHappyContent {
            scope = rememberCoroutineScope()
            CompositionLocalProvider(LocalQrScanner provides scanner) {
                flow = rememberTerminalConnect(
                    approve = { url -> failWith?.let { throw it }; approved += url },
                    onSuccess = { successes++ },
                    onError = if (withOnError) ({ errors++ }) else null,
                )
            }
        }
    }

    private fun setAccount() {
        rule.setHappyContent {
            CompositionLocalProvider(LocalQrScanner provides scanner) {
                flow = rememberAccountLink(
                    approve = { url -> failWith?.let { throw it }; approved += url },
                    onSuccess = { successes++ },
                    onError = { errors++ },
                )
            }
        }
    }

    /** The confirm alert a scan or a pasted terminal link shows first. */
    private fun accept() {
        rule.onNodeWithText("Connect Terminal").assertExists()
        rule.onNodeWithText("Accept Connection").performClick()
    }

    @Test
    fun aScannedTerminalCodeIsApprovedQuietlyOnceAccepted() {
        setTerminal()
        scanner.results += ScanResult.Scanned(terminalUrl)
        rule.runOnIdle { flow.scan() }
        rule.onNodeWithText("Accept Connection").assertExists()
        assertTrue(approved.isEmpty())
        accept()
        rule.waitUntil { successes == 1 }
        assertEquals(listOf(terminalUrl), approved)
        // Success is felt, not announced.
        rule.onNodeWithText("Success").assertDoesNotExist()
        assertFalse(flow.isLoading)
    }

    @Test
    fun anOlderCliCodeIsAskedAboutToo() {
        setTerminal()
        scanner.results += ScanResult.Scanned(legacyTerminalUrl)
        rule.runOnIdle { flow.scan() }
        accept()
        rule.waitUntil { successes == 1 }
        assertEquals(listOf(legacyTerminalUrl), approved)
    }

    @Test
    fun aRejectedScanSendsNothing() {
        setTerminal()
        scanner.results += ScanResult.Scanned(terminalUrl)
        rule.runOnIdle { flow.scan() }
        rule.onNodeWithText("Reject").performClick()
        rule.waitForIdle()
        rule.onNodeWithText("Connect Terminal").assertDoesNotExist()
        assertTrue(approved.isEmpty())
        assertEquals(0, successes)
    }

    @Test
    fun aPastedLinkIsAskedAboutAndRejectSendsNothing() {
        setTerminal()
        rule.runOnIdle { flow.connectWithUrl(terminalUrl) }
        rule.onNodeWithText("Connect Terminal").assertExists()
        rule.onNodeWithText("Reject").performClick()
        rule.waitForIdle()
        assertTrue(approved.isEmpty())
    }

    @Test
    fun theConfirmScreensAcceptDoesNotAskAgain() {
        setTerminal()
        // processAuthUrl is what TerminalConfirmScreen's Accept calls.
        val result = CompletableDeferred<Boolean>()
        rule.runOnIdle { scope.launch { result.complete(flow.processAuthUrl(terminalUrl)) } }
        rule.waitUntil { result.isCompleted }
        rule.onNodeWithText("Accept Connection").assertDoesNotExist()
        assertEquals(listOf(terminalUrl), approved)
    }

    @Test
    fun anAlreadyAnsweredTerminalIsAWarningNotSuccess() {
        failWith = TerminalAlreadyAnsweredException()
        setTerminal(withOnError = true)
        rule.runOnIdle { flow.connectWithUrl(terminalUrl) }
        accept()
        // Shown even to a caller that reports failures itself.
        rule.onNodeWithText("Terminal already connected").assertExists()
        rule.onNodeWithText("Failed to connect terminal").assertDoesNotExist()
        rule.runOnIdle {
            assertEquals(0, successes)
            assertEquals(1, errors)
        }
    }

    @Test
    fun otherCodesCancelsAndFailedScansDoNothing() {
        setTerminal()
        scanner.results += listOf(
            ScanResult.Scanned(accountUrl),
            ScanResult.Scanned("https://example.com"),
            ScanResult.Cancelled,
            ScanResult.Failed("Google Play services are not available"),
        )
        repeat(4) {
            rule.runOnIdle { flow.scan() }
            rule.waitForIdle()
        }
        assertEquals(4, scanner.scans)
        assertTrue(approved.isEmpty())
        assertEquals(0, successes)
        rule.onNodeWithText("Error").assertDoesNotExist()
    }

    @Test
    fun aPastedLinkThatIsNotAValidTerminalLinkIsInvalid() {
        setTerminal()
        for (url in listOf(accountUrl, "happy://terminal?abc", "happy://pair/terminal?key=$key")) {
            rule.runOnIdle { flow.connectWithUrl(url) }
            rule.onNodeWithText("Invalid authentication URL").assertExists()
            rule.onNodeWithText("Connect Terminal").assertDoesNotExist()
            rule.onNodeWithText("OK").performClick()
            rule.onNodeWithText("Invalid authentication URL").assertDoesNotExist()
        }
        assertTrue(approved.isEmpty())
    }

    @Test
    fun aScannedTerminalCodeThatDoesNotParseIsInvalid() {
        setTerminal()
        scanner.results += ScanResult.Scanned("happy://terminal?abc")
        rule.runOnIdle { flow.scan() }
        rule.onNodeWithText("Invalid authentication URL").assertExists()
        assertTrue(approved.isEmpty())
    }

    @Test
    fun aFailedApprovalIsAnAlertUnlessTheCallerReportsIt() {
        failWith = IOException("offline")
        setTerminal()
        rule.runOnIdle { flow.connectWithUrl(terminalUrl) }
        accept()
        rule.onNodeWithText("Failed to connect terminal").assertExists()
        assertEquals(0, successes)
    }

    @Test
    fun aCallerWithOnErrorGetsTheFailureInstead() {
        failWith = IOException("offline")
        setTerminal(withOnError = true)
        rule.runOnIdle { flow.connectWithUrl(terminalUrl) }
        accept()
        rule.waitUntil { errors == 1 }
        rule.onNodeWithText("Failed to connect terminal").assertDoesNotExist()
    }

    @Test
    fun theFlowIsBusyWhileApproving() {
        val gate = CompletableDeferred<Unit>()
        rule.setHappyContent {
            CompositionLocalProvider(LocalQrScanner provides scanner) {
                flow = rememberTerminalConnect(approve = { gate.await() })
            }
        }
        rule.runOnIdle { flow.connectWithUrl(terminalUrl) }
        accept()
        rule.waitUntil { flow.isLoading }
        gate.complete(Unit)
        rule.waitUntil { !flow.isLoading }
    }

    @Test
    fun aLinkedDeviceIsAnnouncedAndOnSuccessWaitsForOk() {
        setAccount()
        scanner.results += ScanResult.Scanned(accountUrl)
        rule.runOnIdle { flow.scan() }
        rule.onNodeWithText("Device linked successfully").assertExists()
        assertEquals(listOf(accountUrl), approved)
        assertEquals(0, successes)
        rule.onNodeWithText("OK").performClick()
        rule.runOnIdle { assertEquals(1, successes) }
    }

    @Test
    fun theAccountScannerIgnoresTerminalCodes() {
        setAccount()
        scanner.results += ScanResult.Scanned(terminalUrl)
        rule.runOnIdle { flow.scan() }
        rule.waitForIdle()
        assertTrue(approved.isEmpty())
    }

    @Test
    fun aFailedLinkIsAnAlertAndOnError() {
        failWith = IOException("offline")
        setAccount()
        rule.runOnIdle { flow.connectWithUrl(accountUrl) }
        rule.onNodeWithText("Failed to link device").assertExists()
        rule.runOnIdle { assertEquals(1, errors) }
    }

    @Test
    fun enterUrlManuallyConnectsWhatWasPasted() {
        var showing by mutableStateOf(true)
        rule.setHappyContent {
            CompositionLocalProvider(LocalQrScanner provides scanner) {
                flow = rememberTerminalConnect(approve = { url -> approved += url })
                if (showing) EnterTerminalUrlPrompt(flow, onDismiss = { showing = false })
            }
        }
        rule.onNodeWithText("Paste the authentication URL from your terminal").assertExists()
        rule.onNodeWithTag(PromptTags.INPUT).performTextInput("  $terminalUrl ")
        rule.onNodeWithText("Authenticate").performClick()
        accept()
        rule.waitUntil { approved.isNotEmpty() }
        assertEquals(listOf(terminalUrl), approved)
        assertFalse(showing)
    }

    @Test
    fun acceptScanKeepsOnlyCodesOfItsKind() {
        assertEquals(terminalUrl, acceptScan(ScanResult.Scanned(terminalUrl), ::isTerminalLink))
        assertEquals(legacyTerminalUrl, acceptScan(ScanResult.Scanned(legacyTerminalUrl), ::isTerminalLink))
        assertNull(acceptScan(ScanResult.Scanned(accountUrl), ::isTerminalLink))
        assertNull(acceptScan(ScanResult.Cancelled, ::isTerminalLink))
        assertNull(acceptScan(ScanResult.Failed("x"), ::isTerminalLink))
    }
}
