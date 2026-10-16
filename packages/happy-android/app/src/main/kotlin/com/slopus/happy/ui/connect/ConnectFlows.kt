package com.slopus.happy.ui.connect

import android.util.Log
import androidx.compose.runtime.Composable
import androidx.compose.runtime.ProvidableCompositionLocal
import androidx.compose.runtime.compositionLocalOf
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
    private val kind: ConnectKind,
    private val scope: CoroutineScope,
) {
    /** A link is being approved (the hooks' `isLoading`). */
    var isLoading by mutableStateOf(false)
        internal set

    internal var alert by mutableStateOf<Alert?>(null)
    internal var errorTitle = ""
    internal var okTitle = ""
    internal var messages = ScanMessages()
    internal var scanner: QrScanner = QrScanner { ScanResult.Cancelled }
    internal var connectAgent: ((String) -> Unit)? = null

    /** No scanner on this device: instead of saying so, Add asks for the link. */
    internal var onUnavailable: (() -> Unit)? = null

    /** Add's "Enter link manually" prompt is open. */
    var enteringLink by mutableStateOf(false)
    internal var process: suspend (String) -> Boolean = { false }

    /** [process], after the person accepts the link when the flow asks first (terminals). */
    internal var confirmAndProcess: suspend (String) -> Boolean = { process(it) }
    private var scanning = false

    /**
     * connectTerminal / connectAccount: opens the scanner and routes the
     * code it reads ([route]). Only a cancel does nothing. Unlike happy-app,
     * a code of another kind or a failed scan says so.
     */
    fun scan() {
        if (scanning) return
        scanning = true
        scope.launch {
            try {
                when (val result = scanner.scan()) {
                    ScanResult.Cancelled -> Unit
                    is ScanResult.Failed -> onUnavailable?.invoke() ?: run { alert = errorAlert(messages.unavailable) }
                    is ScanResult.Scanned -> route(result.value)
                }
            } finally {
                scanning = false
            }
        }
    }

    /**
     * A scanned code by kind: this flow's own is approved, once the person
     * accepts it where the flow asks first, a Protocol V2 pairing code
     * starts pairing, and anything else is an alert naming where it belongs.
     */
    internal suspend fun route(text: String) {
        when (val code = HappyCode.classify(text)) {
            is HappyCode.AgentPairing -> connectAgent?.invoke(code.text)
                ?: run { alert = errorAlert(messages.pairingUnavailable) }
            is HappyCode.Terminal ->
                if (kind == ConnectKind.Terminal || kind == ConnectKind.Add) confirmAndProcess(code.url) else alert = errorAlert(messages.terminalElsewhere)
            is HappyCode.Account -> when (kind) {
                ConnectKind.Account -> confirmAndProcess(code.url)
                ConnectKind.Add -> alert = errorAlert(messages.accountSignedOut)
                else -> alert = errorAlert(messages.accountElsewhere)
            }
            is HappyCode.UnknownHappy, is HappyCode.NotHappy -> alert = errorAlert(messages.notHappy)
        }
    }

    /**
     * connectWithUrl: a pasted link, routed by [route] exactly as the same
     * code read by the camera is, so typing a terminal link into Link New
     * Device names the screen it belongs to instead of calling it invalid.
     * Only a link of no kind this app knows reads differently: it is
     * "Invalid authentication URL", since nothing was scanned.
     */
    fun connectWithUrl(url: String) {
        scope.launch {
            when (HappyCode.classify(url)) {
                is HappyCode.UnknownHappy, is HappyCode.NotHappy -> alert = errorAlert(messages.invalidUrl)
                else -> route(url)
            }
        }
    }

    /**
     * processAuthUrl, awaited, without asking: only for a screen that already
     * showed the request and got Accept. True when the link was approved.
     */
    suspend fun processAuthUrl(url: String): Boolean = process(url)

    internal fun errorAlert(message: String) = Alert(errorTitle, message, listOf(AlertButton(okTitle)))
}

/** Which code a [ConnectFlow] approves itself. */
enum class ConnectKind {
    Terminal,
    Account,

    /**
     * Add, from the first screen or the account menu: a terminal code
     * creates an account that approves it, a pairing code pairs, an account
     * code says it needs a signed-in phone.
     */
    Add;

    /**
     * A link this flow can approve: a terminal link that parses (either
     * form, 32-byte keys), or an account link. Anything else is "Invalid
     * authentication URL".
     */
    internal fun isValid(url: String): Boolean = when (this) {
        Terminal, Add -> parseTerminalLink(url) != null
        Account -> url.startsWith(AccountLink.URL_PREFIX)
    }
}

/** What a scan that can't be approved here says. */
internal data class ScanMessages(
    val unavailable: String = "",
    val notHappy: String = "",
    val terminalElsewhere: String = "",
    val accountElsewhere: String = "",
    val pairingUnavailable: String = "",
    val accountSignedOut: String = "",
    val invalidUrl: String = "",
)

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
    val alreadyConnected = alreadyConnectedAlert()
    return rememberConnectFlow(ConnectKind.Terminal, terminalConfirmation(), approve) { flow, error ->
        when {
            error == null -> {
                haptics.performHapticFeedback(HapticFeedbackType.Confirm)
                currentOnSuccess()
            }
            error is TerminalAlreadyAnsweredException -> {
                // A security warning, not an ordinary failure: always shown.
                flow.alert = alreadyConnected
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
 * Connect Terminal / Accept Connection / Reject: asked before any scanned or
 * pasted terminal code is answered, since a code can come from anywhere.
 */
@Composable
private fun terminalConfirmation() = Confirmation(
    title = stringResource(R.string.terminal_connect_terminal),
    message = stringResource(R.string.terminal_terminal_request_description),
    accept = stringResource(R.string.terminal_accept_connection),
    reject = stringResource(R.string.terminal_reject),
)

/**
 * "Terminal already connected": the terminal's request already had an
 * answer this phone did not send ([TerminalAlreadyAnsweredException]).
 */
@Composable
private fun alreadyConnectedAlert(): Alert = Alert(
    stringResource(R.string.terminal_already_connected_title),
    stringResource(R.string.terminal_already_connected_message),
    listOf(AlertButton(stringResource(R.string.common_ok))),
)

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
    return rememberConnectFlow(ConnectKind.Account, confirmation = null, approve) { flow, error ->
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
 * A flow for [kind]'s links ([ConnectKind.isValid]; anything else is
 * "Invalid authentication URL"). With a [confirmation], scans and pasted
 * links wait for the person's Accept.
 */
@Composable
private fun rememberConnectFlow(
    kind: ConnectKind,
    confirmation: Confirmation?,
    approve: suspend (String) -> Unit,
    onResult: (flow: ConnectFlow, error: Throwable?) -> Unit,
): ConnectFlow {
    val scope = rememberCoroutineScope()
    val flow = remember(kind) { ConnectFlow(kind, scope) }
    val currentApprove by rememberUpdatedState(approve)
    val currentOnResult by rememberUpdatedState(onResult)
    val error = stringResource(R.string.common_error)
    val ok = stringResource(R.string.common_ok)
    val invalid = stringResource(R.string.modals_invalid_auth_url)
    flow.errorTitle = error
    flow.okTitle = ok
    flow.messages = ScanMessages(
        unavailable = stringResource(R.string.scan_unavailable),
        notHappy = stringResource(R.string.scan_not_happy_code),
        terminalElsewhere = stringResource(R.string.scan_terminal_code_elsewhere),
        accountElsewhere = stringResource(R.string.scan_account_code_elsewhere),
        pairingUnavailable = stringResource(R.string.scan_pairing_unavailable),
        accountSignedOut = stringResource(R.string.start_account_code),
        invalidUrl = invalid,
    )
    flow.scanner = rememberQrScanner()
    flow.connectAgent = LocalAgentPairing.current
    flow.process = process@{ url ->
        if (!kind.isValid(url)) {
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
            Log.w("ConnectFlow", "Approving a $kind link failed", e)
            currentOnResult(flow, e)
            false
        } finally {
            flow.isLoading = false
        }
    }
    flow.confirmAndProcess = confirmAndProcess@{ url ->
        if (confirmation == null) return@confirmAndProcess flow.process(url)
        if (!kind.isValid(url)) {
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
 * Add: the first screen's Connect and the account menu's Add
 * ([ConnectKind.Add]). A terminal code, once the person accepts it,
 * creates a Happy account and approves the terminal with it in one step;
 * the account is kept only if the approval went through, and it opens. A
 * pairing code pairs an agent. Without a scanner, or from the first screen's menu, it
 * asks for the link instead ([ConnectFlow.enteringLink]). A failure is an
 * alert; a terminal someone else already answered is the "Terminal already
 * connected" warning.
 */
@Composable
fun rememberAddFlow(graph: AppGraph): ConnectFlow = rememberAddConnect(
    approve = { url ->
        graph.auth.createAccount { account -> approveTerminal(graph.authApi, account.credentials, account.encryption, url) }
    },
)

/** [rememberAddFlow] with the approval passed in, for tests. */
@Composable
fun rememberAddConnect(approve: suspend (url: String) -> Unit): ConnectFlow {
    val haptics = LocalHapticFeedback.current
    val failed = stringResource(R.string.modals_failed_to_connect_terminal)
    val alreadyConnected = alreadyConnectedAlert()
    val flow = rememberConnectFlow(ConnectKind.Add, terminalConfirmation(), approve) { flow, error ->
        when {
            error == null -> haptics.performHapticFeedback(HapticFeedbackType.Confirm)
            error is TerminalAlreadyAnsweredException -> flow.alert = alreadyConnected
            else -> flow.alert = flow.errorAlert(failed)
        }
    }
    flow.onUnavailable = { flow.enteringLink = true }
    if (flow.enteringLink) {
        PromptModal(
            prompt = Prompt(
                title = stringResource(R.string.start_enter_link_title),
                message = stringResource(R.string.start_enter_link_message),
                placeholder = "happy://…",
                confirmText = stringResource(R.string.start_connect),
                onResult = { url -> url?.trim()?.takeIf { it.isNotEmpty() }?.let(flow::connectWithUrl) },
            ),
            onDismiss = { flow.enteringLink = false },
        )
    }
    return flow
}

/** The app's one Add flow, provided by HappyApp; null where nothing provides it (tests). */
val LocalAddFlow: ProvidableCompositionLocal<ConnectFlow?> = compositionLocalOf { null }

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
