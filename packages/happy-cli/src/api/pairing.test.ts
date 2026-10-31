import { describe, expect, it } from 'vitest';
import tweetnacl from 'tweetnacl';
import { createPairingRequest, pairingMobileUrl, pairingWebUrl, verifyPairingResponse } from './pairing';
import { decodeBase64, encodeBase64 } from './encryption';
import { configuration } from '@/configuration';

/** What the Happy app sends: base64(senderPublicKey ‖ nonce ‖ box(payload)), boxed to the CLI's key. */
function boxReply(payload: Uint8Array, recipientPublicKey: Uint8Array): string {
    const sender = tweetnacl.box.keyPair();
    const nonce = tweetnacl.randomBytes(tweetnacl.box.nonceLength);
    const boxed = tweetnacl.box(payload, nonce, recipientPublicKey, sender.secretKey);
    const bundle = new Uint8Array(sender.publicKey.length + nonce.length + boxed.length);
    bundle.set(sender.publicKey, 0);
    bundle.set(nonce, sender.publicKey.length);
    bundle.set(boxed, sender.publicKey.length + nonce.length);
    return encodeBase64(bundle);
}

function payload(...parts: (number | Uint8Array)[]): Uint8Array {
    const bytes = parts.flatMap((part) => typeof part === 'number' ? [part] : Array.from(part));
    return new Uint8Array(bytes);
}

const contentPublicKey = tweetnacl.box.keyPair().publicKey;

describe('verifyPairingResponse', () => {
    it('accepts the app reply 0x03 ‖ contentPublicKey ‖ ps', () => {
        const request = createPairingRequest();
        const response = boxReply(payload(0x03, contentPublicKey, request.pairingSecret), request.keypair.publicKey);

        const result = verifyPairingResponse(response, request.keypair.secretKey, request.pairingSecret);

        expect(result).toEqual({ ok: true, contentPublicKey });
    });

    it('rejects a well-formed reply from someone who knows the public key but not the pairing secret', () => {
        // The server, its database or logs, or another account: they have pk,
        // so the box opens, but they cannot put the right ps in it.
        const request = createPairingRequest();
        const attackerKey = tweetnacl.box.keyPair().publicKey;
        const guessedSecret = tweetnacl.randomBytes(32);
        const response = boxReply(payload(0x03, attackerKey, guessedSecret), request.keypair.publicKey);

        expect(verifyPairingResponse(response, request.keypair.secretKey, request.pairingSecret))
            .toEqual({ ok: false, reason: 'wrong-secret' });
    });

    it('rejects the older 0x00 ‖ contentPublicKey reply', () => {
        const request = createPairingRequest();
        const response = boxReply(payload(0x00, contentPublicKey), request.keypair.publicKey);

        expect(verifyPairingResponse(response, request.keypair.secretKey, request.pairingSecret).ok).toBe(false);
    });

    it('rejects a 32-byte master secret reply', () => {
        const request = createPairingRequest();
        const response = boxReply(tweetnacl.randomBytes(32), request.keypair.publicKey);

        expect(verifyPairingResponse(response, request.keypair.secretKey, request.pairingSecret).ok).toBe(false);
    });

    it('rejects a 65-byte reply with the wrong version byte', () => {
        const request = createPairingRequest();
        const response = boxReply(payload(0x00, contentPublicKey, request.pairingSecret), request.keypair.publicKey);

        expect(verifyPairingResponse(response, request.keypair.secretKey, request.pairingSecret))
            .toEqual({ ok: false, reason: 'wrong-format' });
    });

    it('rejects a reply boxed to another key', () => {
        const request = createPairingRequest();
        const other = createPairingRequest();
        const response = boxReply(payload(0x03, contentPublicKey, request.pairingSecret), other.keypair.publicKey);

        expect(verifyPairingResponse(response, request.keypair.secretKey, request.pairingSecret))
            .toEqual({ ok: false, reason: 'cannot-open' });
    });

    it('rejects a reply that was changed in transit', () => {
        const request = createPairingRequest();
        const bundle = decodeBase64(boxReply(payload(0x03, contentPublicKey, request.pairingSecret), request.keypair.publicKey));
        bundle[bundle.length - 1] ^= 0x01;

        expect(verifyPairingResponse(encodeBase64(bundle), request.keypair.secretKey, request.pairingSecret))
            .toEqual({ ok: false, reason: 'cannot-open' });
    });

    it('rejects empty and junk replies', () => {
        const request = createPairingRequest();
        for (const response of ['', 'not base64 at all', encodeBase64(tweetnacl.randomBytes(137))]) {
            expect(verifyPairingResponse(response, request.keypair.secretKey, request.pairingSecret).ok).toBe(false);
        }
    });
});

describe('pairing URLs', () => {
    it('put the public key and the pairing secret in the mobile URL', () => {
        const request = createPairingRequest();
        const url = new URL(pairingMobileUrl(request));

        expect(url.protocol).toBe('happy:');
        expect(url.host + url.pathname).toBe('pair/terminal');
        expect(decodeBase64(url.searchParams.get('key')!, 'base64url')).toEqual(request.keypair.publicKey);
        expect(decodeBase64(url.searchParams.get('s')!, 'base64url')).toEqual(request.pairingSecret);
    });

    it('put them only in the fragment of the web URL', () => {
        const request = createPairingRequest();
        const url = new URL(pairingWebUrl(request));
        const fragment = new URLSearchParams(url.hash.slice(1));

        expect(`${url.origin}${url.pathname}`).toBe(`${configuration.webappUrl}/terminal/connect`);
        expect(url.search).toBe('');
        expect(fragment.get('v')).toBe('3');
        expect(decodeBase64(fragment.get('key')!, 'base64url')).toEqual(request.keypair.publicKey);
        expect(decodeBase64(fragment.get('s')!, 'base64url')).toEqual(request.pairingSecret);
    });

    it('use a fresh pairing secret for every request', () => {
        expect(createPairingRequest().pairingSecret).not.toEqual(createPairingRequest().pairingSecret);
    });
});
