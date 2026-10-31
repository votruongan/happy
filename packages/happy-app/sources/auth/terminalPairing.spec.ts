import { describe, expect, it } from 'vitest';
import { encodeBase64 } from '@/encryption/base64';
import {
    buildTerminalPairingPayload,
    formatTerminalPairingUrl,
    isTerminalPairingUrl,
    parseTerminalPairingFragment,
    parseTerminalPairingUrl,
} from './terminalPairing';

const pk = new Uint8Array(32).map((_, i) => i + 1);
const ps = new Uint8Array(32).map((_, i) => 200 - i);
const contentPublicKey = new Uint8Array(32).fill(9);
const pkUrl = encodeBase64(pk, 'base64url');
const psUrl = encodeBase64(ps, 'base64url');

describe('parseTerminalPairingUrl', () => {
    it('parses a v3 link with its pairing secret', () => {
        const link = parseTerminalPairingUrl(`happy://pair/terminal?key=${pkUrl}&s=${psUrl}`);
        expect(link).toEqual({ version: 3, publicKey: pk, pairingSecret: ps });
    });

    it('parses a v3 link with the parameters in any order', () => {
        const link = parseTerminalPairingUrl(`happy://pair/terminal?s=${psUrl}&key=${pkUrl}`);
        expect(link?.version).toBe(3);
    });

    it('parses a legacy link as version 2', () => {
        expect(parseTerminalPairingUrl(`happy://terminal?${pkUrl}`)).toEqual({ version: 2, publicKey: pk });
    });

    it('accepts padded base64url keys', () => {
        expect(parseTerminalPairingUrl(`happy://terminal?${pkUrl}=`)).toEqual({ version: 2, publicKey: pk });
    });

    it('rejects a v3 link without the pairing secret instead of downgrading', () => {
        expect(parseTerminalPairingUrl(`happy://pair/terminal?key=${pkUrl}`)).toBeNull();
        expect(parseTerminalPairingUrl(`happy://pair/terminal?key=${pkUrl}&s=`)).toBeNull();
    });

    it('rejects keys and secrets that are not 32 bytes', () => {
        const short = encodeBase64(new Uint8Array(31), 'base64url');
        const long = encodeBase64(new Uint8Array(33), 'base64url');
        expect(parseTerminalPairingUrl(`happy://terminal?${short}`)).toBeNull();
        expect(parseTerminalPairingUrl(`happy://terminal?${long}`)).toBeNull();
        expect(parseTerminalPairingUrl(`happy://pair/terminal?key=${pkUrl}&s=${short}`)).toBeNull();
        expect(parseTerminalPairingUrl(`happy://pair/terminal?key=${long}&s=${psUrl}`)).toBeNull();
    });

    it('rejects junk', () => {
        expect(parseTerminalPairingUrl('')).toBeNull();
        expect(parseTerminalPairingUrl('https://example.com')).toBeNull();
        expect(parseTerminalPairingUrl('happy:///account?' + pkUrl)).toBeNull();
        expect(parseTerminalPairingUrl('happy://terminal?')).toBeNull();
        expect(parseTerminalPairingUrl('happy://terminal?not base64!')).toBeNull();
        expect(parseTerminalPairingUrl(`happy://terminal?${pkUrl}&x=1`)).toBeNull();
    });
});

describe('isTerminalPairingUrl', () => {
    it('matches both link forms only', () => {
        expect(isTerminalPairingUrl(`happy://pair/terminal?key=${pkUrl}&s=${psUrl}`)).toBe(true);
        expect(isTerminalPairingUrl(`happy://terminal?${pkUrl}`)).toBe(true);
        expect(isTerminalPairingUrl(`happy:///account?${pkUrl}`)).toBe(false);
    });
});

describe('parseTerminalPairingFragment', () => {
    it('parses the v3 web fragment', () => {
        expect(parseTerminalPairingFragment(`#v=3&key=${pkUrl}&s=${psUrl}`))
            .toEqual({ version: 3, publicKey: pk, pairingSecret: ps });
    });

    it('parses the legacy web fragment', () => {
        expect(parseTerminalPairingFragment(`#key=${pkUrl}`)).toEqual({ version: 2, publicKey: pk });
    });

    it('never downgrades a fragment that claims v3', () => {
        expect(parseTerminalPairingFragment(`#v=3&key=${pkUrl}`)).toBeNull();
        expect(parseTerminalPairingFragment(`#key=${pkUrl}&s=${psUrl}`)).toBeNull();
        expect(parseTerminalPairingFragment(`#v=2&key=${pkUrl}`)).toBeNull();
    });

    it('rejects an empty fragment', () => {
        expect(parseTerminalPairingFragment('')).toBeNull();
        expect(parseTerminalPairingFragment('#')).toBeNull();
    });
});

describe('formatTerminalPairingUrl', () => {
    it('round-trips both link forms', () => {
        const v3 = parseTerminalPairingUrl(`happy://pair/terminal?key=${pkUrl}&s=${psUrl}`)!;
        const v2 = parseTerminalPairingUrl(`happy://terminal?${pkUrl}`)!;
        expect(parseTerminalPairingUrl(formatTerminalPairingUrl(v3))).toEqual(v3);
        expect(parseTerminalPairingUrl(formatTerminalPairingUrl(v2))).toEqual(v2);
    });
});

describe('buildTerminalPairingPayload', () => {
    it('builds 0x03 ‖ contentPublicKey ‖ ps for a v3 link', () => {
        const payload = buildTerminalPairingPayload({ version: 3, publicKey: pk, pairingSecret: ps }, contentPublicKey);
        expect(payload.length).toBe(65);
        expect(payload[0]).toBe(0x03);
        expect(payload.slice(1, 33)).toEqual(contentPublicKey);
        expect(payload.slice(33, 65)).toEqual(ps);
    });

    it('builds 0x00 ‖ contentPublicKey for a legacy link', () => {
        const payload = buildTerminalPairingPayload({ version: 2, publicKey: pk }, contentPublicKey);
        expect(payload.length).toBe(33);
        expect(payload[0]).toBe(0x00);
        expect(payload.slice(1)).toEqual(contentPublicKey);
    });

    it('never builds a 32-byte (master secret shaped) payload', () => {
        for (const link of [{ version: 3 as const, publicKey: pk, pairingSecret: ps }, { version: 2 as const, publicKey: pk }]) {
            expect(buildTerminalPairingPayload(link, contentPublicKey).length).not.toBe(32);
        }
    });

    it('rejects a content public key of the wrong size', () => {
        expect(() => buildTerminalPairingPayload({ version: 2, publicKey: pk }, new Uint8Array(31))).toThrow();
    });
});
