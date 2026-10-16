import { encodeBase64 } from '@/encryption/base64';
import { decryptBox } from '@/encryption/libsodium';
import { decodePairingKey } from './terminalPairing';

/**
 * Account linking: a new device (phone, web, desktop) joins the account by
 * showing a QR code that a device already in the account scans.
 *
 * The new device shows `happy://pair/account?key=<pk>&s=<ps>` (base64url).
 * `pk` is its one-time box public key, which the server also has. `ps` is a
 * one-time pairing secret that is only in the QR code and in the new
 * device's memory. It never goes to the server. The existing device replies
 * with
 *
 *     box(0x04 ‖ masterSecret(32) ‖ ps(32), pk)
 *
 * and the new device accepts the reply only if it carries `ps`, so a reply
 * that the server, its database, the network or another account wrote cannot
 * sign it in to a different account.
 *
 * The older `happy:///account?<pk>` link is refused on both sides: it has no
 * `ps`, so its reply cannot be checked. Restoring with the secret key still
 * works.
 */

export const ACCOUNT_PAIRING_URL_PREFIX = 'happy://pair/account?';
export const LEGACY_ACCOUNT_URL_PREFIX = 'happy:///account?';

const KEY_LENGTH = 32;
const REPLY_ACCOUNT_V3 = 0x04;
const PAYLOAD_LENGTH = 1 + KEY_LENGTH + KEY_LENGTH;
// encryptBox bundle: ephemeral public key(32) ‖ nonce(24) ‖ box(payload + 16-byte tag)
const REPLY_BUNDLE_LENGTH = KEY_LENGTH + 24 + PAYLOAD_LENGTH + 16;

export interface AccountPairingLink {
    publicKey: Uint8Array;
    pairingSecret: Uint8Array;
}

export function isAccountPairingUrl(url: string): boolean {
    return url.startsWith(ACCOUNT_PAIRING_URL_PREFIX);
}

/** An account link from a version of Happy that does not send a pairing secret. */
export function isLegacyAccountUrl(url: string): boolean {
    return url.startsWith(LEGACY_ACCOUNT_URL_PREFIX);
}

/** Parses a scanned account link. Returns null for anything malformed, and for legacy links. */
export function parseAccountPairingUrl(url: string): AccountPairingLink | null {
    if (!isAccountPairingUrl(url)) {
        return null;
    }
    const params = new URLSearchParams(url.slice(ACCOUNT_PAIRING_URL_PREFIX.length));
    const publicKey = decodePairingKey(params.get('key'));
    const pairingSecret = decodePairingKey(params.get('s'));
    if (!publicKey || !pairingSecret) {
        return null;
    }
    return { publicKey, pairingSecret };
}

/** The URL the new device shows as a QR code. */
export function formatAccountPairingUrl(link: AccountPairingLink): string {
    const key = encodeBase64(link.publicKey, 'base64url');
    return `${ACCOUNT_PAIRING_URL_PREFIX}key=${key}&s=${encodeBase64(link.pairingSecret, 'base64url')}`;
}

/** The plaintext the existing device boxes to `link.publicKey`. */
export function buildAccountPairingPayload(link: AccountPairingLink, masterSecret: Uint8Array): Uint8Array {
    if (masterSecret.length !== KEY_LENGTH) {
        throw new Error('Master secret must be 32 bytes');
    }
    if (link.pairingSecret.length !== KEY_LENGTH) {
        throw new Error('Pairing secret must be 32 bytes');
    }
    const payload = new Uint8Array(PAYLOAD_LENGTH);
    payload[0] = REPLY_ACCOUNT_V3;
    payload.set(masterSecret, 1);
    payload.set(link.pairingSecret, 1 + KEY_LENGTH);
    return payload;
}

/**
 * Opens the reply to this device's account link request. Returns the master
 * secret only if the reply opens with `secretKey`, is an account reply, and
 * carries this request's `pairingSecret`. Returns null for anything else.
 */
export function openAccountPairingReply(bundle: Uint8Array, secretKey: Uint8Array, pairingSecret: Uint8Array): Uint8Array | null {
    if (bundle.length !== REPLY_BUNDLE_LENGTH || pairingSecret.length !== KEY_LENGTH) {
        return null;
    }
    const payload = decryptBox(bundle, secretKey);
    if (!payload || payload.length !== PAYLOAD_LENGTH || payload[0] !== REPLY_ACCOUNT_V3) {
        return null;
    }
    if (!constantTimeEqual(payload.subarray(1 + KEY_LENGTH), pairingSecret)) {
        return null;
    }
    return payload.slice(1, 1 + KEY_LENGTH);
}

function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length) {
        return false;
    }
    let diff = 0;
    for (let i = 0; i < a.length; i++) {
        diff |= a[i] ^ b[i];
    }
    return diff === 0;
}
