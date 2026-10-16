import { decodeBase64, encodeBase64 } from '@/encryption/base64';

/**
 * Terminal pairing links, and the reply this app sends back to a terminal.
 *
 * Current CLIs show `happy://pair/terminal?key=<pk>&s=<ps>` (base64url).
 * `pk` is the CLI's one-time box public key, which the server also has.
 * `ps` is a one-time pairing secret that is only in the QR code or URL and
 * in the CLI's memory. It never goes to the server. The reply carries `ps`
 * inside the box:
 *
 *     0x03 ‖ contentPublicKey(32) ‖ ps(32)
 *
 * so the CLI can reject a reply that the server, its database, the network
 * or another account wrote.
 *
 * Older CLIs show `happy://terminal?<pk>` and get the V2 reply
 * `0x00 ‖ contentPublicKey(32)`.
 *
 * Neither reply contains the account master secret. Only the link picks the
 * reply; nothing the server says can change it.
 */

export const TERMINAL_PAIRING_URL_PREFIX = 'happy://pair/terminal?';
export const LEGACY_TERMINAL_URL_PREFIX = 'happy://terminal?';

const KEY_LENGTH = 32;
const REPLY_V2 = 0x00;
const REPLY_V3 = 0x03;

export type TerminalPairingLink =
    | { version: 3; publicKey: Uint8Array; pairingSecret: Uint8Array }
    | { version: 2; publicKey: Uint8Array };

export function isTerminalPairingUrl(url: string): boolean {
    return url.startsWith(TERMINAL_PAIRING_URL_PREFIX) || url.startsWith(LEGACY_TERMINAL_URL_PREFIX);
}

/** Parses a scanned, pasted or deep-linked terminal URL. Returns null for anything malformed. */
export function parseTerminalPairingUrl(url: string): TerminalPairingLink | null {
    if (url.startsWith(TERMINAL_PAIRING_URL_PREFIX)) {
        return parseV3(new URLSearchParams(url.slice(TERMINAL_PAIRING_URL_PREFIX.length)));
    }
    if (url.startsWith(LEGACY_TERMINAL_URL_PREFIX)) {
        const publicKey = decodePairingKey(url.slice(LEGACY_TERMINAL_URL_PREFIX.length));
        return publicKey ? { version: 2, publicKey } : null;
    }
    return null;
}

/**
 * Parses the fragment of the web connect page: `#v=3&key=<pk>&s=<ps>` from
 * current CLIs, `#key=<pk>` from older ones. A fragment that says v3 or has
 * `s` must be a complete v3 link; it never falls back to the old reply.
 */
export function parseTerminalPairingFragment(hash: string): TerminalPairingLink | null {
    const params = new URLSearchParams(hash.startsWith('#') ? hash.slice(1) : hash);
    if (params.has('v') || params.has('s')) {
        return params.get('v') === '3' ? parseV3(params) : null;
    }
    const publicKey = decodePairingKey(params.get('key'));
    return publicKey ? { version: 2, publicKey } : null;
}

/** The canonical URL for a parsed link, for screens that hand a URL to useConnectTerminal. */
export function formatTerminalPairingUrl(link: TerminalPairingLink): string {
    const key = encodeBase64(link.publicKey, 'base64url');
    if (link.version === 3) {
        return `${TERMINAL_PAIRING_URL_PREFIX}key=${key}&s=${encodeBase64(link.pairingSecret, 'base64url')}`;
    }
    return `${LEGACY_TERMINAL_URL_PREFIX}${key}`;
}

/** The plaintext to box to `link.publicKey`. */
export function buildTerminalPairingPayload(link: TerminalPairingLink, contentPublicKey: Uint8Array): Uint8Array {
    if (contentPublicKey.length !== KEY_LENGTH) {
        throw new Error('Content public key must be 32 bytes');
    }
    if (link.version === 3) {
        const payload = new Uint8Array(1 + KEY_LENGTH + KEY_LENGTH);
        payload[0] = REPLY_V3;
        payload.set(contentPublicKey, 1);
        payload.set(link.pairingSecret, 1 + KEY_LENGTH);
        return payload;
    }
    const payload = new Uint8Array(1 + KEY_LENGTH);
    payload[0] = REPLY_V2;
    payload.set(contentPublicKey, 1);
    return payload;
}

function parseV3(params: URLSearchParams): TerminalPairingLink | null {
    const publicKey = decodePairingKey(params.get('key'));
    const pairingSecret = decodePairingKey(params.get('s'));
    if (!publicKey || !pairingSecret) {
        return null;
    }
    return { version: 3, publicKey, pairingSecret };
}

/** Strict base64url decode of a 32-byte link value. The base64 helpers are lenient, so check the alphabet and the decoded length. */
export function decodePairingKey(value: string | null): Uint8Array | null {
    if (!value || !/^[A-Za-z0-9_-]+={0,2}$/.test(value)) {
        return null;
    }
    try {
        const bytes = decodeBase64(value, 'base64url');
        return bytes.length === KEY_LENGTH ? bytes : null;
    } catch {
        return null;
    }
}
