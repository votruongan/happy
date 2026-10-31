import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

const { post } = vi.hoisted(() => ({ post: vi.fn() }));

vi.mock('axios', () => ({
    default: {
        post,
        isAxiosError: (e: any) => e?.isAxiosError === true,
    },
}));
vi.mock('expo-crypto', () => ({
    getRandomBytes: (n: number) => new Uint8Array(require('crypto').randomBytes(n)),
}));
vi.mock('@/encryption/libsodium.lib', () => ({ default: require('libsodium-wrappers') }));
vi.mock('@/sync/serverConfig', () => ({ getServerUrl: () => 'https://server.test' }));
vi.mock('@/sync/apiSocket', () => ({ getHappyClientId: () => 'test-client' }));

import sodium from '@/encryption/libsodium.lib';
import { encodeBase64 } from '@/encryption/base64';
import { encryptBox } from '@/encryption/libsodium';
import { buildAccountPairingPayload } from './accountPairing';
import { generateAuthKeyPair, type QRAuthKeyPair } from './authQRStart';
import { AUTH_QR_TIMEOUT_MS, authQRWait } from './authQRWait';
import { AccountLinkAlreadyAnsweredError, authAccountApprove } from './authAccountApprove';

const masterSecret = new Uint8Array(32).fill(7);

function authorized(bundle: Uint8Array) {
    return { data: { state: 'authorized', token: 'token-1', response: encodeBase64(bundle) } };
}

function payload(tag: number, secret: Uint8Array, pairingSecret: Uint8Array) {
    const out = new Uint8Array(65);
    out[0] = tag;
    out.set(secret, 1);
    out.set(pairingSecret, 33);
    return out;
}

let keypair: QRAuthKeyPair;

beforeAll(async () => {
    await sodium.ready;
});

beforeEach(() => {
    post.mockReset();
    keypair = generateAuthKeyPair();
});

afterEach(() => {
    vi.useRealTimers();
});

describe('generateAuthKeyPair', () => {
    it('makes a fresh 32-byte pairing secret for each request', () => {
        const other = generateAuthKeyPair();
        expect(keypair.pairingSecret.length).toBe(32);
        expect(keypair.pairingSecret).not.toEqual(other.pairingSecret);
    });
});

describe('authQRWait', () => {
    it('signs in with the master secret from a reply that carries the pairing secret', async () => {
        post.mockResolvedValueOnce({ data: { state: 'requested' } });
        post.mockResolvedValueOnce(authorized(encryptBox(buildAccountPairingPayload(keypair, masterSecret), keypair.publicKey)));
        vi.useFakeTimers();

        const pending = authQRWait(keypair);
        await vi.advanceTimersByTimeAsync(1000);
        const result = await pending;

        expect(result).toEqual({ status: 'authorized', credentials: { secret: masterSecret, token: 'token-1' } });
        // The pairing secret never goes to the server.
        for (const [, body] of post.mock.calls) {
            expect(body).toEqual({ publicKey: encodeBase64(keypair.publicKey) });
        }
    });

    it('rejects a forged reply with the wrong pairing secret, and stops polling', async () => {
        post.mockResolvedValue(authorized(encryptBox(payload(0x04, masterSecret, new Uint8Array(32).fill(1)), keypair.publicKey)));

        expect(await authQRWait(keypair)).toEqual({ status: 'rejected' });
        expect(post).toHaveBeenCalledTimes(1);
    });

    it('rejects a terminal reply (tag 0x03) that carries the pairing secret', async () => {
        post.mockResolvedValue(authorized(encryptBox(payload(0x03, masterSecret, keypair.pairingSecret), keypair.publicKey)));

        expect(await authQRWait(keypair)).toEqual({ status: 'rejected' });
    });

    it('rejects the legacy reply, a boxed 32-byte master secret', async () => {
        post.mockResolvedValue(authorized(encryptBox(masterSecret, keypair.publicKey)));

        expect(await authQRWait(keypair)).toEqual({ status: 'rejected' });
    });

    it('rejects a response that is not a box at all', async () => {
        post.mockResolvedValue({ data: { state: 'authorized', token: 'token-1', response: 'not base64!' } });
        expect(await authQRWait(keypair)).toEqual({ status: 'rejected' });

        post.mockResolvedValue({ data: { state: 'authorized', token: 'token-1' } });
        expect(await authQRWait(keypair)).toEqual({ status: 'rejected' });
    });

    it('expires when no reply comes within the timeout', async () => {
        post.mockResolvedValue({ data: { state: 'requested' } });
        vi.useFakeTimers();

        const pending = authQRWait(keypair);
        await vi.advanceTimersByTimeAsync(AUTH_QR_TIMEOUT_MS + 1000);

        expect(await pending).toEqual({ status: 'expired' });
        expect(post.mock.calls.length).toBeLessThanOrEqual(AUTH_QR_TIMEOUT_MS / 1000 + 1);
    });

    it('stops when cancelled', async () => {
        expect(await authQRWait(keypair, undefined, () => true)).toEqual({ status: 'cancelled' });
        expect(post).not.toHaveBeenCalled();
    });

    it('fails on a network error', async () => {
        post.mockRejectedValue(new Error('offline'));
        expect(await authQRWait(keypair)).toEqual({ status: 'failed' });
    });
});

describe('authAccountApprove', () => {
    it('reports a 409 as an answer that someone else already gave', async () => {
        post.mockRejectedValue({ isAxiosError: true, response: { status: 409 } });
        await expect(authAccountApprove('token', keypair.publicKey, new Uint8Array(137)))
            .rejects.toBeInstanceOf(AccountLinkAlreadyAnsweredError);
    });

    it('passes other errors through', async () => {
        post.mockRejectedValue({ isAxiosError: true, response: { status: 404 } });
        await expect(authAccountApprove('token', keypair.publicKey, new Uint8Array(137)))
            .rejects.not.toBeInstanceOf(AccountLinkAlreadyAnsweredError);
    });
});
