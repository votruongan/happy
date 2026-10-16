
import axios from 'axios';
import { encodeBase64 } from "../encryption/base64";
import { getServerUrl } from "@/sync/serverConfig";
import { getHappyClientId } from "@/sync/apiSocket";

interface AuthRequestStatus {
    status: 'not_found' | 'pending' | 'authorized';
    supportsV2: boolean;
}

/**
 * The terminal's pairing request already has an answer that this app did not
 * send. Someone else may have connected the terminal, so it must not be
 * treated as success.
 */
export class TerminalAlreadyAnsweredError extends Error {
    constructor() {
        super('Terminal auth request was already answered');
        this.name = 'TerminalAlreadyAnsweredError';
    }
}

/**
 * Sends `response` (already boxed to `publicKey`) as the answer to a
 * terminal's pairing request. The caller picks the reply from the pairing
 * link; the server's `supportsV2` flag is ignored, so the server cannot make
 * this app send a different reply.
 */
export async function authApprove(token: string, publicKey: Uint8Array, response: Uint8Array) {
    const API_ENDPOINT = getServerUrl();
    const publicKeyBase64 = encodeBase64(publicKey);

    const statusResponse = await axios.get<AuthRequestStatus>(
        `${API_ENDPOINT}/v1/auth/request/status`,
        {
            params: {
                publicKey: publicKeyBase64
            },
            headers: {
                'X-Happy-Client': getHappyClientId(),
            }
        }
    );

    const { status } = statusResponse.data;
    if (status === 'authorized') {
        throw new TerminalAlreadyAnsweredError();
    }
    if (status !== 'pending') {
        throw new Error('Terminal auth request not found');
    }

    try {
        await axios.post(`${API_ENDPOINT}/v1/auth/response`, {
            publicKey: publicKeyBase64,
            response: encodeBase64(response)
        }, {
            headers: {
                'Authorization': `Bearer ${token}`,
                'X-Happy-Client': getHappyClientId(),
            }
        });
    } catch (e) {
        // Servers that store only the first answer reply 409 to any later one.
        if (axios.isAxiosError(e) && e.response?.status === 409) {
            throw new TerminalAlreadyAnsweredError();
        }
        throw e;
    }
}
