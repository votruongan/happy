import { beforeAll, describe, expect, it, vi } from 'vitest';

vi.mock('expo-crypto', () => ({
    getRandomBytes: (n: number) => new Uint8Array(require('crypto').randomBytes(n)),
}));
vi.mock('@/encryption/libsodium.lib', () => ({ default: require('libsodium-wrappers') }));

import sodium from '@/encryption/libsodium.lib';
import { encodeBase64 } from '@/encryption/base64';
import { encryptBox } from '@/encryption/libsodium';
import {
    buildAccountPairingPayload,
    formatAccountPairingUrl,
    isAccountPairingUrl,
    isLegacyAccountUrl,
    openAccountPairingReply,
    parseAccountPairingUrl,
} from './accountPairing';

const pk = new Uint8Array(32).map((_, i) => i + 1);
const ps = new Uint8Array(32).map((_, i) => 200 - i);
const masterSecret = new Uint8Array(32).fill(7);
const pkUrl = encodeBase64(pk, 'base64url');
const psUrl = encodeBase64(ps, 'base64url');

beforeAll(async () => {
    await sodium.ready;
});

describe('parseAccountPairingUrl', () => {
    it('parses an account link with its pairing secret', () => {
        expect(parseAccountPairingUrl(`happy://pair/account?key=${pkUrl}&s=${psUrl}`))
            .toEqual({ publicKey: pk, pairingSecret: ps });
    });

    it('parses the parameters in any order', () => {
        expect(parseAccountPairingUrl(`happy://pair/account?s=${psUrl}&key=${pkUrl}`))
            .toEqual({ publicKey: pk, pairingSecret: ps });
    });

    it('refuses the legacy link, which has no pairing secret', () => {
        expect(parseAccountPairingUrl(`happy:///account?${pkUrl}`)).toBeNull();
    });

    it('rejects a link without the pairing secret', () => {
        expect(parseAccountPairingUrl(`happy://pair/account?key=${pkUrl}`)).toBeNull();
        expect(parseAccountPairingUrl(`happy://pair/account?key=${pkUrl}&s=`)).toBeNull();
    });

    it('rejects keys and secrets that are not 32 bytes', () => {
        const short = encodeBase64(new Uint8Array(31), 'base64url');
        const long = encodeBase64(new Uint8Array(33), 'base64url');
        expect(parseAccountPairingUrl(`happy://pair/account?key=${short}&s=${psUrl}`)).toBeNull();
        expect(parseAccountPairingUrl(`happy://pair/account?key=${long}&s=${psUrl}`)).toBeNull();
        expect(parseAccountPairingUrl(`happy://pair/account?key=${pkUrl}&s=${short}`)).toBeNull();
        expect(parseAccountPairingUrl(`happy://pair/account?key=${pkUrl}&s=${long}`)).toBeNull();
    });

    it('rejects terminal links and junk', () => {
        expect(parseAccountPairingUrl(`happy://pair/terminal?key=${pkUrl}&s=${psUrl}`)).toBeNull();
        expect(parseAccountPairingUrl(`happy://terminal?${pkUrl}`)).toBeNull();
        expect(parseAccountPairingUrl('')).toBeNull();
        expect(parseAccountPairingUrl('happy://pair/account?')).toBeNull();
        expect(parseAccountPairingUrl(`happy://pair/account?key=not base64!&s=${psUrl}`)).toBeNull();
    });
});

describe('isAccountPairingUrl / isLegacyAccountUrl', () => {
    it('tells the current and the legacy link apart', () => {
        expect(isAccountPairingUrl(`happy://pair/account?key=${pkUrl}&s=${psUrl}`)).toBe(true);
        expect(isAccountPairingUrl(`happy:///account?${pkUrl}`)).toBe(false);
        expect(isLegacyAccountUrl(`happy:///account?${pkUrl}`)).toBe(true);
        expect(isLegacyAccountUrl(`happy://pair/account?key=${pkUrl}&s=${psUrl}`)).toBe(false);
        expect(isAccountPairingUrl(`happy://pair/terminal?key=${pkUrl}&s=${psUrl}`)).toBe(false);
    });
});

describe('formatAccountPairingUrl', () => {
    it('formats the link that the new device shows, and round-trips', () => {
        const url = formatAccountPairingUrl({ publicKey: pk, pairingSecret: ps });
        expect(url).toBe(`happy://pair/account?key=${pkUrl}&s=${psUrl}`);
        expect(parseAccountPairingUrl(url)).toEqual({ publicKey: pk, pairingSecret: ps });
    });
});

describe('buildAccountPairingPayload', () => {
    it('builds 0x04 ‖ masterSecret ‖ ps', () => {
        const payload = buildAccountPairingPayload({ publicKey: pk, pairingSecret: ps }, masterSecret);
        expect(payload.length).toBe(65);
        expect(payload[0]).toBe(0x04);
        expect(payload.slice(1, 33)).toEqual(masterSecret);
        expect(payload.slice(33, 65)).toEqual(ps);
    });

    it('rejects a master secret of the wrong size', () => {
        expect(() => buildAccountPairingPayload({ publicKey: pk, pairingSecret: ps }, new Uint8Array(31))).toThrow();
    });
});

describe('openAccountPairingReply', () => {
    function request() {
        const keypair = sodium.crypto_box_keypair();
        const pairingSecret = new Uint8Array(require('crypto').randomBytes(32));
        return { publicKey: keypair.publicKey, secretKey: keypair.privateKey, pairingSecret };
    }

    function payload(tag: number, secret: Uint8Array, pairingSecret: Uint8Array) {
        const out = new Uint8Array(65);
        out[0] = tag;
        out.set(secret, 1);
        out.set(pairingSecret, 33);
        return out;
    }

    it('returns the master secret from a reply built for this request', () => {
        const req = request();
        const bundle = encryptBox(buildAccountPairingPayload(req, masterSecret), req.publicKey);
        expect(bundle.length).toBe(137);
        expect(openAccountPairingReply(bundle, req.secretKey, req.pairingSecret)).toEqual(masterSecret);
    });

    it('rejects a reply with the wrong pairing secret', () => {
        const req = request();
        const bundle = encryptBox(payload(0x04, masterSecret, new Uint8Array(32).fill(1)), req.publicKey);
        expect(openAccountPairingReply(bundle, req.secretKey, req.pairingSecret)).toBeNull();
    });

    it('rejects a reply that differs from the pairing secret in its last byte only', () => {
        const req = request();
        const wrong = req.pairingSecret.slice();
        wrong[31] ^= 1;
        const bundle = encryptBox(payload(0x04, masterSecret, wrong), req.publicKey);
        expect(openAccountPairingReply(bundle, req.secretKey, req.pairingSecret)).toBeNull();
    });

    it('rejects a terminal reply (tag 0x03), even with the right pairing secret', () => {
        const req = request();
        const bundle = encryptBox(payload(0x03, masterSecret, req.pairingSecret), req.publicKey);
        expect(openAccountPairingReply(bundle, req.secretKey, req.pairingSecret)).toBeNull();
    });

    it('rejects the legacy reply, a boxed 32-byte master secret', () => {
        const req = request();
        const bundle = encryptBox(masterSecret, req.publicKey);
        expect(openAccountPairingReply(bundle, req.secretKey, req.pairingSecret)).toBeNull();
    });

    it('rejects a reply boxed to another key', () => {
        const req = request();
        const other = request();
        const bundle = encryptBox(buildAccountPairingPayload(req, masterSecret), other.publicKey);
        expect(openAccountPairingReply(bundle, req.secretKey, req.pairingSecret)).toBeNull();
    });

    it('rejects a tampered or resized bundle', () => {
        const req = request();
        const bundle = encryptBox(buildAccountPairingPayload(req, masterSecret), req.publicKey);
        const tampered = bundle.slice();
        tampered[100] ^= 1;
        expect(openAccountPairingReply(tampered, req.secretKey, req.pairingSecret)).toBeNull();
        expect(openAccountPairingReply(bundle.slice(0, 136), req.secretKey, req.pairingSecret)).toBeNull();
        const longer = new Uint8Array(138);
        longer.set(bundle);
        expect(openAccountPairingReply(longer, req.secretKey, req.pairingSecret)).toBeNull();
    });
});
