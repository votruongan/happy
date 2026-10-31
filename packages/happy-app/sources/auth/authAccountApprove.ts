import axios from 'axios';
import { encodeBase64 } from "../encryption/base64";
import { getServerUrl } from "@/sync/serverConfig";
import { getHappyClientId } from "@/sync/apiSocket";

/**
 * The new device's link request already has an answer that this app did not
 * send. Someone else may have answered it, so it must not be treated as
 * success.
 */
export class AccountLinkAlreadyAnsweredError extends Error {
    constructor() {
        super('Account link request was already answered');
        this.name = 'AccountLinkAlreadyAnsweredError';
    }
}

/** Sends `answer` (already boxed to `publicKey`) as the answer to a new device's account link request. */
export async function authAccountApprove(token: string, publicKey: Uint8Array, answer: Uint8Array) {
    const API_ENDPOINT = getServerUrl();
    try {
        await axios.post(`${API_ENDPOINT}/v1/auth/account/response`, {
            publicKey: encodeBase64(publicKey),
            response: encodeBase64(answer)
        }, {
            headers: {
                'Authorization': `Bearer ${token}`,
                'X-Happy-Client': getHappyClientId(),
            }
        });
    } catch (e) {
        // Servers that store only the first answer reply 409 to any later one.
        if (axios.isAxiosError(e) && e.response?.status === 409) {
            throw new AccountLinkAlreadyAnsweredError();
        }
        throw e;
    }
}
