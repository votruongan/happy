import axios from 'axios';
import { decodeBase64, encodeBase64 } from '../encryption/base64';
import { getServerUrl } from '@/sync/serverConfig';
import { QRAuthKeyPair } from './authQRStart';
import { openAccountPairingReply } from './accountPairing';
import { getHappyClientId } from '@/sync/apiSocket';

export interface AuthCredentials {
    secret: Uint8Array;
    token: string;
}

/** How long one QR code waits for a reply. */
export const AUTH_QR_TIMEOUT_MS = 120_000;

export type AuthQRWaitResult =
    | { status: 'authorized'; credentials: AuthCredentials }
    // A reply came, but it did not carry this QR code's pairing secret, so it
    // did not come from a device that scanned the code. Nothing was saved.
    | { status: 'rejected' }
    // No reply within AUTH_QR_TIMEOUT_MS. Show a new code.
    | { status: 'expired' }
    | { status: 'cancelled' }
    | { status: 'failed' };

/**
 * Waits for a device in the account to answer this account link request.
 * Accepts only a reply that `openAccountPairingReply` verifies. On any other
 * reply it stops: the server decides what comes next, so polling on would
 * only let it try again.
 */
export async function authQRWait(keypair: QRAuthKeyPair, onProgress?: (dots: number) => void, shouldCancel?: () => boolean): Promise<AuthQRWaitResult> {
    let dots = 0;
    const serverUrl = getServerUrl();
    const deadline = Date.now() + AUTH_QR_TIMEOUT_MS;

    while (true) {
        if (shouldCancel && shouldCancel()) {
            return { status: 'cancelled' };
        }
        if (Date.now() >= deadline) {
            return { status: 'expired' };
        }

        let data: any;
        try {
            const response = await axios.post(`${serverUrl}/v1/auth/account/request`, {
                publicKey: encodeBase64(keypair.publicKey),
            }, {
                headers: {
                    'X-Happy-Client': getHappyClientId(),
                }
            });
            data = response.data;
        } catch (error) {
            console.log('\n\nFailed to check authentication status. Please try again.');
            return { status: 'failed' };
        }

        if (data?.state === 'authorized') {
            const secret = typeof data.response === 'string' ? openReply(data.response, keypair) : null;
            if (!secret || typeof data.token !== 'string') {
                console.log('\n\nRejected an account link reply that did not come from the scanning device.');
                return { status: 'rejected' };
            }
            console.log('\n\n✓ Authentication successful\n');
            return { status: 'authorized', credentials: { secret, token: data.token } };
        }

        // Call progress callback if provided
        if (onProgress) {
            onProgress(dots);
        }
        dots++;

        // Wait 1 second before next check
        await new Promise(resolve => setTimeout(resolve, 1000));
    }
}

function openReply(response: string, keypair: QRAuthKeyPair): Uint8Array | null {
    let bundle: Uint8Array;
    try {
        bundle = decodeBase64(response);
    } catch {
        return null;
    }
    return openAccountPairingReply(bundle, keypair.secretKey, keypair.pairingSecret);
}
