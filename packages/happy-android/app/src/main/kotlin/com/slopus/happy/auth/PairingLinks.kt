package com.slopus.happy.auth

import com.slopus.happy.crypto.Base64Variant
import com.slopus.happy.crypto.decodeBase64
import com.slopus.happy.crypto.encodeBase64
import java.net.URLDecoder

/**
 * Terminal pairing links, and the reply this phone sends back to a terminal
 * (happy-app's auth/terminalPairing.ts).
 *
 * Current CLIs show `happy://pair/terminal?key=<pk>&s=<ps>` (base64url).
 * `pk` is the CLI's one-time box public key, which the server also has. `ps`
 * is a one-time pairing secret that is only in the QR code or URL and in the
 * CLI's memory; it never goes to the server. The reply carries `ps` inside
 * the box:
 *
 *     0x03 || contentPublicKey(32) || ps(32)
 *
 * so the CLI can reject a reply that this phone did not write.
 *
 * Older CLIs show `happy://terminal?<pk>` and get `0x00 || contentPublicKey(32)`.
 *
 * Neither reply contains the account secret. Only the link picks the reply;
 * nothing the server says can change it.
 */
sealed class TerminalLink(val publicKey: ByteArray) {
    /** `happy://pair/terminal?key=<pk>&s=<ps>`. */
    class V3(publicKey: ByteArray, val pairingSecret: ByteArray) : TerminalLink(publicKey) {
        override fun equals(other: Any?) =
            other is V3 && publicKey.contentEquals(other.publicKey) && pairingSecret.contentEquals(other.pairingSecret)

        override fun hashCode() = 31 * publicKey.contentHashCode() + pairingSecret.contentHashCode()
    }

    /** `happy://terminal?<pk>`, from CLIs older than pairing v3. */
    class Legacy(publicKey: ByteArray) : TerminalLink(publicKey) {
        override fun equals(other: Any?) = other is Legacy && publicKey.contentEquals(other.publicKey)

        override fun hashCode() = publicKey.contentHashCode()
    }

    /** The canonical URL for this link. */
    val url: String
        get() = when (val link = this) {
            is V3 -> "${TERMINAL_PAIRING_URL_PREFIX}key=${encodeKey(link.publicKey)}&s=${encodeKey(link.pairingSecret)}"
            is Legacy -> LEGACY_TERMINAL_URL_PREFIX + encodeKey(link.publicKey)
        }

    /** The plaintext to box to [publicKey]. */
    fun reply(contentPublicKey: ByteArray): ByteArray {
        require(contentPublicKey.size == KEY_LENGTH) { "Content public key must be $KEY_LENGTH bytes" }
        return when (val link = this) {
            is V3 -> byteArrayOf(REPLY_V3) + contentPublicKey + link.pairingSecret
            is Legacy -> byteArrayOf(REPLY_V2) + contentPublicKey
        }
    }

    override fun toString() = javaClass.simpleName
}

/** What current CLIs show: `happy://pair/terminal?key=<pk>&s=<ps>`. */
const val TERMINAL_PAIRING_URL_PREFIX = "happy://pair/terminal?"

/** What CLIs older than pairing v3 show: `happy://terminal?<pk>`. */
const val LEGACY_TERMINAL_URL_PREFIX = "happy://terminal?"

/** Has either terminal link prefix. A scanner keeps only these; [parseTerminalLink] decides if one is valid. */
fun isTerminalLink(url: String): Boolean =
    url.startsWith(TERMINAL_PAIRING_URL_PREFIX) || url.startsWith(LEGACY_TERMINAL_URL_PREFIX)

/** A scanned, pasted or deep-linked terminal URL. Null for anything malformed. */
fun parseTerminalLink(url: String): TerminalLink? = when {
    url.startsWith(TERMINAL_PAIRING_URL_PREFIX) -> {
        val params = queryParams(url.substring(TERMINAL_PAIRING_URL_PREFIX.length))
        terminalLink(params["key"], params["s"] ?: "")
    }
    url.startsWith(LEGACY_TERMINAL_URL_PREFIX) -> terminalLink(url.substring(LEGACY_TERMINAL_URL_PREFIX.length), null)
    else -> null
}

/**
 * A link from its parts, as a deep link carries them: base64url [publicKey]
 * and, for v3, [pairingSecret]. A v3 link with a missing or malformed secret
 * is null, never a legacy link.
 */
fun terminalLink(publicKey: String?, pairingSecret: String?): TerminalLink? {
    val key = decodeKey(publicKey) ?: return null
    if (pairingSecret == null) return TerminalLink.Legacy(key)
    return decodeKey(pairingSecret)?.let { TerminalLink.V3(key, it) }
}

private const val KEY_LENGTH = 32
private const val REPLY_V2: Byte = 0x00
private const val REPLY_V3: Byte = 0x03
private val BASE64_URL = Regex("^[A-Za-z0-9_-]+={0,2}$")

private fun encodeKey(bytes: ByteArray) = encodeBase64(bytes, Base64Variant.Url)

// Check the alphabet and the decoded length: the key goes on the wire as is.
private fun decodeKey(value: String?): ByteArray? {
    if (value == null || !BASE64_URL.matches(value)) return null
    return try {
        decodeBase64(value, Base64Variant.Url).takeIf { it.size == KEY_LENGTH }
    } catch (_: IllegalArgumentException) {
        null
    }
}

/** URLSearchParams: each name's first value, `+` and `%xx` decoded. */
private fun queryParams(query: String): Map<String, String> {
    val params = LinkedHashMap<String, String>()
    for (pair in query.split('&')) {
        if (pair.isEmpty()) continue
        val name = decode(pair.substringBefore('='))
        params.putIfAbsent(name, if ('=' in pair) decode(pair.substringAfter('=')) else "")
    }
    return params
}

private fun decode(value: String): String = try {
    URLDecoder.decode(value, "UTF-8") // The Charset overload is API 33.
} catch (_: IllegalArgumentException) {
    value
}
