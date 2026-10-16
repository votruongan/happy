package com.slopus.happy.ui.connect

import android.util.Log
import androidx.compose.runtime.Composable
import androidx.compose.runtime.Stable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.setValue
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.res.stringResource
import com.slopus.happy.AppGraph
import com.slopus.happy.R
import com.slopus.happy.auth.AuthState
import com.slopus.happy.auth.TerminalAlreadyAnsweredException
import com.slopus.happy.auth.approveAccountLink
import com.slopus.happy.auth.approveTerminal
import com.slopus.happy.auth.isTerminalLink
import com.slopus.happy.auth.parseTerminalLink
import com.slopus.happy.crypto.AccountLink
import com.slopus.happy.ui.components.Alert
import com.slopus.happy.ui.components.AlertButton
import com.slopus.happy.ui.components.HappyAlert
import com.slopus.happy.ui.components.Prompt
import com.slopus.happy.ui.components.PromptModal
import com.slopus.happy.ui.components.confirm
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.launch

/**
 * One connect flow on screen: scan a QR code or take a pasted link, approve
 * it, and say so. [rememberTerminalConnect] and [rememberAccountLink] make
 * them; each shows its own alerts while it is composed.
 */
@Stable
class ConnectFlow internal constructor(
    private val scope: CoroutineScope,
) {
    /** A link is being approved (the hooks' `isLoading`). */
    var isLoading by mutableStateOf(false)
        internal set

    internal var alert by mutableStateOf<Alert?>(null)
    internal var errorTitle = ""
    internal var okTitle = ""
    internal var scanner: QrScanner = QrScanner { ScanResult.Cancelled }

    /** The codes a scan keeps (its kind's prefix). */
    internal var accepts: (String) -> Boolean = { false }
    internal var process: suspend (String) -> Boolean = { false }

    /** [process], after the person accepts the link when the flow asks first (terminals). */
    internal var confirmAndProcess: suspend (String) -> Boolean = { process(it) }
    private var scanning = false

    /**
     * connectTerminal / connectAccount: opens the scanner and approves the
     * code it reads, once the person accepts it. Codes of the other kind, a
     * cancel and a failed scan do nothing, as in happy-app.
     */
    fun scan() {
        if (scanning) return
        scanning = true
        scope.launch {
            try {
                acceptScan(scanner.scan(), accepts)?.let { confirmAndProcess(it) }
            } finally {
                scanning = false
            }
        }
    }

    /**
     * connectWithUrl: a pasted link, approved once the person accepts it.
     * Anything that is not a valid link of the flow's kind is "Invalid
     * authentication URL".
     */
    fun connectWithUrl(url: String) {
        scope.launch { confirmAndProcess(url) }
    }

    /**
     * processAuthUrl, awaited, without asking: only for a screen that already
     * showed the request and got Accept. True when the link was approved.
     */
    suspend fun processAuthUrl(url: String): Boolean = process(url)

    internal fun errorAlert(message: String) = Alert(errorTitle, message, listOf(AlertButton(okTitle)))
}

/**
 * useConnectTerminal.ts: connects a terminal (the CLI or Happy Desktop) to
 * this account. A scan or a pasted link asks the person to accept the
 * request first. Success is felt, not announced (a haptic, then
 * [onSuccess]); a failure is an alert unless [onError] reports it in the
 * caller's own UI. A request someone else already answered is always a
 * warning alert, and [onError] too.
 */
@Composable
fun rememberTerminalConnect(
    graph: AppGraph,
    onSuccess: () -> Unit = {},
    onError: (() -> Unit)? = null,
): ConnectFlow = rememberTerminalConnect(
    approve = { url ->
        val account = graph.auth.state.value as? AuthState.SignedIn ?: error("Signed out")
        approveTerminal(graph.authApi, account.credentials, account.encryption, url)
    },
    onSuccess = onSuccess,
    onError = onError,
)

/** [rememberTerminalConnect] with the approval passed in, for tests. */
@Composable
fun rememberTerminalConnect(
    approve: suspend (url: String) -> Unit,
    onSuccess: () -> Unit = {},
    onError: (() -> Unit)? = null,
): ConnectFlow {
    val haptics = LocalHapticFeedback.current
    val currentOnSuccess by rememberUpdatedState(onSuccess)
    val currentOnError by rememberUpdatedState(onError)
    val failed = stringResource(R.string.modals_failed_to_connect_terminal)
    val alreadyConnectedTitle = stringResource(R.string.terminal_already_connected_title)
    val alreadyConnected = stringResource(R.string.terminal_already_connected_message)
    val ok = stringResource(R.string.common_ok)
    val confirmation = Confirmation(
        title = stringResource(R.string.terminal_connect_terminal),
        message = stringResource(R.string.terminal_terminal_request_description),
        accept = stringResource(R.string.terminal_accept_connection),
        reject = stringResource(R.string.terminal_reject),
    )
    return rememberConnectFlow(
        accepts = ::isTerminalLink,
        valid = { parseTerminalLink(it) != null },
        confirmation = confirmation,
        approve = approve,
    ) { flow, error ->
        when {
            error == null -> {
                haptics.performHapticFeedback(HapticFeedbackType.Confirm)
                currentOnSuccess()
            }
            error is TerminalAlreadyAnsweredException -> {
                // A security warning, not an ordinary failure: always shown.
                flow.alert = Alert(alreadyConnectedTitle, alreadyConnected, listOf(AlertButton(ok)))
                currentOnError?.invoke()
            }
            else -> {
                val handler = currentOnError
                if (handler != null) handler() else flow.alert = flow.errorAlert(failed)
            }
        }
    }
}

/**
 * useConnectAccount.ts: Settings › Account › Link New Device. Approves a
 * new phone that shows `happy:///account?…` by handing it this account's
 * secret. Success and failure are both alerts; [onSuccess] runs when the
 * success alert is closed.
 */
@Composable
fun rememberAccountLink(
    graph: AppGraph,
    onSuccess: () -> Unit = {},
    onError: () -> Unit = {},
): ConnectFlow = rememberAccountLink(
    approve = { url ->
        val account = graph.auth.state.value as? AuthState.SignedIn ?: error("Signed out")
        approveAccountLink(graph.authApi, account.credentials, url)
    },
    onSuccess = onSuccess,
    onError = onError,
)

/** [rememberAccountLink] with the approval passed in, for tests. */
@Composable
fun rememberAccountLink(
    approve: suspend (url: String) -> Unit,
    onSuccess: () -> Unit = {},
    onError: () -> Unit = {},
): ConnectFlow {
    val currentOnSuccess by rememberUpdatedState(onSuccess)
    val currentOnError by rememberUpdatedState(onError)
    val successTitle = stringResource(R.string.common_success)
    val linked = stringResource(R.string.modals_device_linked_successfully)
    val ok = stringResource(R.string.common_ok)
    val failed = stringResource(R.string.modals_failed_to_link_device)
    val isAccountLink = { url: String -> url.startsWith(AccountLink.URL_PREFIX) }
    return rememberConnectFlow(accepts = isAccountLink, valid = isAccountLink, confirmation = null, approve = approve) { flow, error ->
        if (error == null) {
            flow.alert = Alert(successTitle, linked, listOf(AlertButton(ok) { currentOnSuccess() }))
        } else {
            flow.alert = flow.errorAlert(failed)
            currentOnError()
        }
    }
}

/** The question a flow asks before it approves a scanned or pasted link (Modal.confirm). */
private class Confirmation(val title: String, val message: String, val accept: String, val reject: String)

/**
 * A flow for links that [accepts] (the scanner keeps only those) and
 * [valid] (anything else is "Invalid authentication URL"). With a
 * [confirmation], scans and pasted links wait for the person's Accept.
 */
@Composable
private fun rememberConnectFlow(
    accepts: (String) -> Boolean,
    valid: (String) -> Boolean,
    confirmation: Confirmation?,
    approve: suspend (String) -> Unit,
    onResult: (flow: ConnectFlow, error: Throwable?) -> Unit,
): ConnectFlow {
    val scope = rememberCoroutineScope()
    val flow = remember { ConnectFlow(scope) }
    val currentApprove by rememberUpdatedState(approve)
    val currentOnResult by rememberUpdatedState(onResult)
    val error = stringResource(R.string.common_error)
    val ok = stringResource(R.string.common_ok)
    val invalid = stringResource(R.string.modals_invalid_auth_url)
    flow.errorTitle = error
    flow.okTitle = ok
    flow.scanner = rememberQrScanner()
    flow.accepts = accepts
    flow.process = process@{ url ->
        if (!valid(url)) {
            flow.alert = flow.errorAlert(invalid)
            return@process false
        }
        flow.isLoading = true
        try {
            currentApprove(url)
            currentOnResult(flow, null)
            true
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            // Never the link itself: a terminal link carries its pairing secret.
            Log.w("ConnectFlow", "Approving a link failed", e)
            currentOnResult(flow, e)
            false
        } finally {
            flow.isLoading = false
        }
    }
    flow.confirmAndProcess = confirmAndProcess@{ url ->
        if (confirmation == null) return@confirmAndProcess flow.process(url)
        if (!valid(url)) {
            flow.alert = flow.errorAlert(invalid)
            return@confirmAndProcess false
        }
        val accepted = confirm(
            show = { flow.alert = it },
            title = confirmation.title,
            message = confirmation.message,
            confirmText = confirmation.accept,
            cancelText = confirmation.reject,
        )
        accepted && flow.process(url)
    }
    flow.alert?.let { HappyAlert(it, onDismiss = { flow.alert = null }) }
    return flow
}


/**
 * Settings' "Enter URL manually" (SettingsView.tsx): the prompt for a
 * terminal's auth link, then [flow]'s `connectWithUrl`. Show it while the
 * row's state says so; [onDismiss] runs when it closes either way.
 */
@Composable
fun EnterTerminalUrlPrompt(flow: ConnectFlow, onDismiss: () -> Unit) {
    PromptModal(
        prompt = Prompt(
            title = stringResource(R.string.modals_authenticate_terminal),
            message = stringResource(R.string.modals_paste_url_from_terminal),
            placeholder = "happy://pair/terminal?...",
            confirmText = stringResource(R.string.common_authenticate),
            onResult = { url -> url?.trim()?.takeIf { it.isNotEmpty() }?.let(flow::connectWithUrl) },
        ),
        onDismiss = onDismiss,
    )
}
