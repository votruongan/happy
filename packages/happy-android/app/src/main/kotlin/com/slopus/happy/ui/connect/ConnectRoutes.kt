package com.slopus.happy.ui.connect

import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.compose.composable
import androidx.navigation.toRoute
import com.slopus.happy.AppGraph
import com.slopus.happy.auth.TerminalLink
import com.slopus.happy.auth.terminalLink
import com.slopus.happy.crypto.Base64Variant
import com.slopus.happy.crypto.encodeBase64
import com.slopus.happy.ui.HomeRoute
import kotlinx.coroutines.launch
import kotlinx.serialization.Serializable

/**
 * terminal/index.tsx: confirm a terminal that asked by link. A v3 link has
 * [pairingSecret]; an older CLI's link doesn't.
 */
@Serializable data class TerminalRoute(val publicKey: String? = null, val pairingSecret: String? = null) {
    /** The link to answer, or null when it doesn't parse ("Invalid Connection Link"). */
    val link: TerminalLink? get() = publicKey?.let { terminalLink(it, pairingSecret) }

    // The pairing secret is only for the answer, never for logs.
    override fun toString() = "TerminalRoute"
}

/** terminal/connect.tsx: the CLI's web link, opened in the app. */
@Serializable data object TerminalWebRoute

/** The signed-in connect screens. HappyApp's NavHost calls this once. */
fun NavGraphBuilder.connectRoutes(graph: AppGraph, nav: NavHostController) {
    composable<TerminalRoute> { entry ->
        val link = remember(entry) { entry.toRoute<TerminalRoute>().link }
        val scope = rememberCoroutineScope()
        val connect = rememberTerminalConnect(graph, onSuccess = { nav.popBackStack() })
        TerminalConfirmScreen(
            publicKey = link?.let { encodeBase64(it.publicKey, Base64Variant.Url) },
            connecting = connect.isLoading,
            // The screen itself asked, so Accept answers at once.
            onAccept = {
                if (link != null) scope.launch { connect.processAuthUrl(link.url) }
            },
            onReject = { nav.popBackStack() },
        )
    }
    composable<TerminalWebRoute> { TerminalWebScreen(onBack = { nav.popBackStack() }) }
}

/**
 * Takes links from [DeepLinks] once the screens are up and opens their
 * screen over the current one; Home goes back to Home. Signed out, only
 * the screens that work without an account open (happy-app pushes the
 * others too, onto screens with nothing loaded); the rest are dropped.
 * Session links go to [onOpenSession], which the chat screen provides;
 * without it they are dropped too. Protocol V2 pairing codes open signed
 * in or out, through [LocalAgentPairing].
 */
@Composable
fun DeepLinkEffect(nav: NavHostController, signedIn: Boolean, onOpenSession: ((String) -> Unit)? = null) {
    val pending by DeepLinks.pending.collectAsStateWithLifecycle()
    val connectAgent = LocalAgentPairing.current
    LaunchedEffect(pending, signedIn) {
        val link = pending ?: return@LaunchedEffect
        if (!DeepLinks.consume(link)) return@LaunchedEffect
        if (link is DeepLink.AgentPairing) {
            connectAgent?.invoke(link.code)
            return@LaunchedEffect
        }
        if (!signedIn) {
            if (link is DeepLink.Screen && link.signedOut) nav.navigate(link.route)
            return@LaunchedEffect
        }
        when (link) {
            is DeepLink.Terminal -> nav.navigate(TerminalRoute(link.publicKey, link.pairingSecret))
            DeepLink.TerminalWeb -> nav.navigate(TerminalWebRoute)
            is DeepLink.Session -> onOpenSession?.invoke(link.id)
            is DeepLink.Screen -> nav.navigate(link.route)
            DeepLink.Home -> nav.popBackStack(HomeRoute, inclusive = false)
            is DeepLink.AgentPairing -> Unit
        }
    }
}
