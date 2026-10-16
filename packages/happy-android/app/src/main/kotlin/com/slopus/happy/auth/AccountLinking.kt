package com.slopus.happy.auth

import com.slopus.happy.crypto.AccountEncryption
import com.slopus.happy.crypto.AccountLink
import com.slopus.happy.crypto.Base64Variant
import com.slopus.happy.crypto.RandomSource
import com.slopus.happy.crypto.SecureRandomSource
import com.slopus.happy.crypto.Sodium
import com.slopus.happy.crypto.decodeBase64
import com.slopus.happy.crypto.encryptBox
import com.slopus.happy.net.HttpStatusException
import kotlinx.coroutines.delay
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

/** What the other phone handed over: the account secret and a token for it. */
class LinkedAccount(val token: String, val secret: ByteArray)

/**
 * The new phone's side of an account link (restore/index.tsx with
 * authQRStart.ts and authQRWait.ts). It offers [url] as a QR code; the phone
 * that has the account scans it and seals the secret to [keyPair].
 */
class AccountLinkRequest(
    private val api: AuthApi,
    random: RandomSource = SecureRandomSource,
) {
    val keyPair: Sodium.KeyPair = AccountLink.generateKeyPair(random)

    /** What the QR code carries: `happy:///account?<base64url public key>`. */
    val url: String = AccountLink.linkUrl(keyPair.publicKey)

    /** authQRStart: registers the request. Throws if the server can't be reached. */
    suspend fun start() {
        api.requestAccountLink(keyPair.publicKey)
    }

    /**
     * authQRWait: asks again until the request is authorized, at once and
     * then every [pollInterval]. Null when the answer doesn't open with this
     * key pair; throws when a request fails, as authQRWait gives up then too.
     */
    suspend fun awaitApproval(pollInterval: Duration = 1.seconds): LinkedAccount? {
        while (true) {
            val state = api.requestAccountLink(keyPair.publicKey)
            if (state.state == "authorized") {
                val token = state.token ?: return null
                val response = state.response?.let {
                    try {
                        decodeBase64(it)
                    } catch (_: IllegalArgumentException) {
                        null
                    }
                } ?: return null
                val secret = AccountLink.openSecret(response, keyPair) ?: return null
                return LinkedAccount(token, secret)
            }
            delay(pollInterval)
        }
    }
}

/** A scanned or pasted link that is not the kind the flow expects. */
class InvalidLinkException(message: String) : IllegalArgumentException(message)

/**
 * The existing phone's side (useConnectAccount.ts processAuthUrl with
 * authAccountApprove.ts): seals this account's secret to the key in a
 * `happy:///account?` link and posts it.
 *
 * Throws [InvalidLinkException] for anything that is not an account link
 * (happy-app's "Invalid authentication URL"), and any other exception when the
 * key is malformed or the request fails ("Failed to link device").
 */
suspend fun approveAccountLink(
    api: AuthApi,
    credentials: AuthCredentials,
    url: String,
    random: RandomSource = SecureRandomSource,
) {
    if (!url.startsWith(AccountLink.URL_PREFIX)) throw InvalidLinkException("Not an account link")
    val publicKey = decodeBase64(url.substring(AccountLink.URL_PREFIX.length), Base64Variant.Url)
    val response = AccountLink.sealSecret(credentials.secretBytes(), publicKey, random)
    api.approveAccountLink(credentials.token, publicKey, response)
}

/**
 * The terminal's pairing request already has an answer that this phone did
 * not send (status `authorized`, or 409 from the server). Someone else may
 * have connected the terminal, so it is a warning, not success.
 */
class TerminalAlreadyAnsweredException : IllegalStateException("Terminal auth request was already answered")

/**
 * Connecting a terminal (useConnectTerminal.ts processAuthUrl with
 * authApprove.ts). The terminal waits with a box key pair; this phone seals
 * the reply its link asks for ([TerminalLink.reply]) to it. The reply never
 * holds the account secret, and the server's `supportsV2` flag is not read,
 * so nothing the server says changes what is sent.
 *
 * Throws [InvalidLinkException] when [url] is not a valid terminal link,
 * [TerminalAlreadyAnsweredException] when the request already has another
 * answer, and any other exception when the request is gone or fails.
 */
suspend fun approveTerminal(
    api: AuthApi,
    credentials: AuthCredentials,
    encryption: AccountEncryption,
    url: String,
    random: RandomSource = SecureRandomSource,
) {
    val link = parseTerminalLink(url) ?: throw InvalidLinkException("Not a terminal link")
    val response = encryptBox(link.reply(encryption.contentPublicKey), link.publicKey, random)
    when (api.terminalAuthStatus(link.publicKey).status) {
        "pending" -> Unit
        "authorized" -> throw TerminalAlreadyAnsweredException()
        else -> throw IllegalStateException("Terminal auth request not found")
    }
    try {
        api.approveTerminal(credentials.token, link.publicKey, response)
    } catch (e: HttpStatusException) {
        // The server keeps only the first answer and turns any other away with 409.
        if (e.status == 409) throw TerminalAlreadyAnsweredException()
        throw e
    }
}
