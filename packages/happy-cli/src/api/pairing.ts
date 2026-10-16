import { randomBytes, timingSafeEqual } from 'node:crypto';
import tweetnacl from 'tweetnacl';
import { decodeBase64, encodeBase64Url } from '@/api/encryption';
import { configuration } from '@/configuration';

/**
 * Terminal pairing (v3): how a new CLI gets the account's content public key
 * from the user's Happy app.
 *
 * The CLI makes a one-time box keypair (pk, sk) and a one-time pairing secret
 * ps. The server gets pk (POST /v1/auth/request). ps goes only into the QR
 * code or URL that the user's app reads; it never goes to the server:
 *
 *     happy://pair/terminal?key=<b64url pk>&s=<b64url ps>
 *     <webappUrl>/terminal/connect#v=3&key=<b64url pk>&s=<b64url ps>
 *
 * The app answers with box(0x03 ‖ contentPublicKey(32) ‖ ps(32), pk) from a
 * fresh sender key, sent as base64 of
 * senderPublicKey(32) ‖ nonce(24) ‖ ciphertext(65 + 16), 137 bytes.
 *
 * Anyone who knows pk (the server, its database or logs, the network) can
 * write a box that opens with sk. Only an app that read the QR code knows ps,
 * so a reply counts only if it carries ps. Nothing else is accepted: not a
 * 32-byte master secret, not the older 0x00 ‖ contentPublicKey reply.
 */

export const PAIRING_TIMEOUT_MS = 120_000;

const KEY_LENGTH = 32;
const REPLY_V3 = 0x03;
const PAYLOAD_LENGTH = 1 + KEY_LENGTH + KEY_LENGTH;
const BUNDLE_LENGTH = KEY_LENGTH + tweetnacl.box.nonceLength + PAYLOAD_LENGTH + tweetnacl.box.overheadLength;

export interface PairingRequest {
    keypair: tweetnacl.BoxKeyPair;
    pairingSecret: Uint8Array;
}

export type PairingVerification =
    | { ok: true; contentPublicKey: Uint8Array }
    | { ok: false; reason: 'wrong-length' | 'cannot-open' | 'wrong-format' | 'wrong-secret' };

export function createPairingRequest(): PairingRequest {
    return {
        keypair: tweetnacl.box.keyPair.fromSecretKey(new Uint8Array(randomBytes(KEY_LENGTH))),
        pairingSecret: new Uint8Array(randomBytes(KEY_LENGTH)),
    };
}

/** The URL in the QR code, also shown for manual entry in the mobile app. */
export function pairingMobileUrl(request: PairingRequest): string {
    return `happy://pair/terminal?key=${encodeBase64Url(request.keypair.publicKey)}&s=${encodeBase64Url(request.pairingSecret)}`;
}

/** The web app URL. The link is in the fragment, so the web host never receives it. */
export function pairingWebUrl(request: PairingRequest): string {
    return `${configuration.webappUrl}/terminal/connect#v=3&key=${encodeBase64Url(request.keypair.publicKey)}&s=${encodeBase64Url(request.pairingSecret)}`;
}

/**
 * Checks a pairing reply from the server. Returns the content public key only
 * if the reply opens with `secretKey`, has the v3 format, and carries
 * `pairingSecret`.
 */
export function verifyPairingResponse(response: string, secretKey: Uint8Array, pairingSecret: Uint8Array): PairingVerification {
    const bundle = decodeBase64(response);
    if (bundle.length !== BUNDLE_LENGTH) {
        return { ok: false, reason: 'wrong-length' };
    }
    const senderPublicKey = bundle.subarray(0, KEY_LENGTH);
    const nonce = bundle.subarray(KEY_LENGTH, KEY_LENGTH + tweetnacl.box.nonceLength);
    const ciphertext = bundle.subarray(KEY_LENGTH + tweetnacl.box.nonceLength);
    const payload = tweetnacl.box.open(ciphertext, nonce, senderPublicKey, secretKey);
    if (!payload) {
        return { ok: false, reason: 'cannot-open' };
    }
    if (payload.length !== PAYLOAD_LENGTH || payload[0] !== REPLY_V3) {
        return { ok: false, reason: 'wrong-format' };
    }
    if (!timingSafeEqual(payload.subarray(1 + KEY_LENGTH), pairingSecret)) {
        return { ok: false, reason: 'wrong-secret' };
    }
    return { ok: true, contentPublicKey: payload.slice(1, 1 + KEY_LENGTH) };
}
