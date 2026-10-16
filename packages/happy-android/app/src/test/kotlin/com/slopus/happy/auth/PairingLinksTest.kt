package com.slopus.happy.auth

import com.slopus.happy.crypto.Base64Variant
import com.slopus.happy.crypto.encodeBase64
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Terminal links and replies, as happy-app's terminalPairing.spec.ts checks them. */
class PairingLinksTest {
    private val pk = ByteArray(32) { (it + 1).toByte() }
    private val ps = ByteArray(32) { (200 - it).toByte() }
    private val contentPublicKey = ByteArray(32) { 9 }
    private val pkUrl = encodeBase64(pk, Base64Variant.Url)
    private val psUrl = encodeBase64(ps, Base64Variant.Url)

    @Test
    fun aV3LinkCarriesItsPairingSecret() {
        assertEquals(TerminalLink.V3(pk, ps), parseTerminalLink("happy://pair/terminal?key=$pkUrl&s=$psUrl"))
        assertEquals(TerminalLink.V3(pk, ps), parseTerminalLink("happy://pair/terminal?s=$psUrl&key=$pkUrl"))
    }

    @Test
    fun anOlderCliLinkIsLegacy() {
        assertEquals(TerminalLink.Legacy(pk), parseTerminalLink("happy://terminal?$pkUrl"))
        assertEquals(TerminalLink.Legacy(pk), parseTerminalLink("happy://terminal?$pkUrl="))
    }

    @Test
    fun aV3LinkWithoutItsSecretIsInvalidNotLegacy() {
        assertNull(parseTerminalLink("happy://pair/terminal?key=$pkUrl"))
        assertNull(parseTerminalLink("happy://pair/terminal?key=$pkUrl&s="))
        assertNull(terminalLink(pkUrl, ""))
        assertNull(terminalLink(pkUrl, "not base64!"))
    }

    @Test
    fun keysAndSecretsMustBe32Bytes() {
        val short = encodeBase64(ByteArray(31), Base64Variant.Url)
        val long = encodeBase64(ByteArray(33), Base64Variant.Url)
        assertNull(parseTerminalLink("happy://terminal?$short"))
        assertNull(parseTerminalLink("happy://terminal?$long"))
        assertNull(parseTerminalLink("happy://pair/terminal?key=$pkUrl&s=$short"))
        assertNull(parseTerminalLink("happy://pair/terminal?key=$long&s=$psUrl"))
    }

    @Test
    fun junkIsNotALink() {
        assertNull(parseTerminalLink(""))
        assertNull(parseTerminalLink("https://example.com"))
        assertNull(parseTerminalLink("happy:///account?$pkUrl"))
        assertNull(parseTerminalLink("happy://terminal?"))
        assertNull(parseTerminalLink("happy://terminal?not base64!"))
        assertNull(parseTerminalLink("happy://terminal?$pkUrl&x=1"))
        // Standard base64 is not the link's alphabet.
        assertNull(parseTerminalLink("happy://terminal?" + encodeBase64(ByteArray(32) { -1 })))
    }

    @Test
    fun scannersKeepBothLinkFormsOnly() {
        assertTrue(isTerminalLink("happy://pair/terminal?key=$pkUrl&s=$psUrl"))
        assertTrue(isTerminalLink("happy://terminal?$pkUrl"))
        assertFalse(isTerminalLink("happy:///account?$pkUrl"))
    }

    @Test
    fun aLinkRoundTripsThroughItsUrl() {
        for (link in listOf(TerminalLink.V3(pk, ps), TerminalLink.Legacy(pk))) {
            assertEquals(link, parseTerminalLink(link.url))
        }
    }

    @Test
    fun aV3ReplyIsTheContentKeyAndThePairingSecret() {
        val reply = TerminalLink.V3(pk, ps).reply(contentPublicKey)
        assertEquals(65, reply.size)
        assertEquals(3, reply[0].toInt())
        assertArrayEquals(contentPublicKey, reply.copyOfRange(1, 33))
        assertArrayEquals(ps, reply.copyOfRange(33, 65))
    }

    @Test
    fun aLegacyReplyIsTheContentKey() {
        val reply = TerminalLink.Legacy(pk).reply(contentPublicKey)
        assertArrayEquals(byteArrayOf(0) + contentPublicKey, reply)
    }

    @Test
    fun noReplyIsShapedLikeTheAccountSecret() {
        for (link in listOf(TerminalLink.V3(pk, ps), TerminalLink.Legacy(pk))) {
            assertNotEquals(32, link.reply(contentPublicKey).size)
        }
    }

    @Test(expected = IllegalArgumentException::class)
    fun aContentKeyOfTheWrongSizeIsRefused() {
        TerminalLink.Legacy(pk).reply(ByteArray(31))
    }

    @Test
    fun aLinkNeverPrintsItsSecret() {
        assertFalse(psUrl in TerminalLink.V3(pk, ps).toString())
    }
}
