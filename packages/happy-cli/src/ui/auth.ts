import { encodeBase64 } from "@/api/encryption";
import { configuration } from "@/configuration";
import { randomBytes } from "node:crypto";
import axios from 'axios';
import { displayQRCode } from "./qrcode";
import { delay } from "@/utils/time";
import { readCredentials, updateSettings, Credentials, writeCredentialsDataKey } from "@/persistence";
import { createPairingRequest, PairingRequest, pairingMobileUrl, pairingWebUrl, PAIRING_TIMEOUT_MS, verifyPairingResponse } from "@/api/pairing";
import { openBrowser } from "@/utils/browser";
import { AuthSelector, AuthMethod } from "./ink/AuthSelector";
import { render } from 'ink';
import React from 'react';
import { randomUUID } from 'node:crypto';
import { logger } from './logger';

export async function doAuth(): Promise<Credentials | null> {
    console.clear();

    // Show authentication method selector
    const authMethod = await selectAuthenticationMethod();
    if (!authMethod) {
        console.log('\nAuthentication cancelled.\n');
        process.exit(0);
    }

    // One-time keypair and pairing secret (see api/pairing.ts). Only the
    // public key goes to the server; the pairing secret is only in the QR
    // code / URL.
    const request = createPairingRequest();

    // Create a new authentication request
    try {
        if (process.env.DEBUG) {
            console.log(`[AUTH DEBUG] Sending auth request to: ${configuration.serverUrl}/v1/auth/request`);
            console.log(`[AUTH DEBUG] Public key: ${encodeBase64(request.keypair.publicKey).substring(0, 20)}...`);
        }
        await axios.post(`${configuration.serverUrl}/v1/auth/request`, {
            publicKey: encodeBase64(request.keypair.publicKey),
            supportsV2: true,
            pairingVersion: 3
        }, {
            headers: {
                'X-Happy-Client': `cli/${configuration.currentCliVersion}`
            }
        });
        if (process.env.DEBUG) {
            console.log(`[AUTH DEBUG] Auth request sent successfully`);
        }
    } catch (error) {
        if (process.env.DEBUG) {
            console.log(`[AUTH DEBUG] Failed to send auth request:`, error);
        }
        console.log('Failed to create authentication request, please try again later.');
        return null;
    }

    // Handle authentication based on selected method
    if (authMethod === 'mobile') {
        return await doMobileAuth(request);
    } else {
        return await doWebAuth(request);
    }
}

/**
 * Display authentication method selector and return user choice
 */
function selectAuthenticationMethod(): Promise<AuthMethod | null> {
    return new Promise((resolve) => {
        let hasResolved = false;

        const onSelect = (method: AuthMethod) => {
            if (!hasResolved) {
                hasResolved = true;
                app.unmount();
                resolve(method);
            }
        };

        const onCancel = () => {
            if (!hasResolved) {
                hasResolved = true;
                app.unmount();
                resolve(null);
            }
        };

        const app = render(React.createElement(AuthSelector, { onSelect, onCancel }), {
            exitOnCtrlC: false,
            patchConsole: false
        });
    });
}

/**
 * Handle mobile authentication flow
 */
async function doMobileAuth(request: PairingRequest): Promise<Credentials | null> {
    console.clear();
    console.log('\nMobile Authentication\n');
    console.log('Scan this QR code with your Happy mobile app:\n');

    const authUrl = pairingMobileUrl(request);
    displayQRCode(authUrl);

    console.log('\nOr manually enter this URL:');
    console.log(authUrl);
    console.log('');
    console.log('This code connects this computer to your account. Do not share it.');
    console.log('It needs an up-to-date Happy app.');
    console.log('');

    return await waitForAuthentication(request);
}

/**
 * Handle web authentication flow
 */
async function doWebAuth(request: PairingRequest): Promise<Credentials | null> {
    console.clear();
    console.log('\nWeb Authentication\n');

    const webUrl = pairingWebUrl(request);
    console.log('Opening your browser...');

    const browserOpened = await openBrowser(webUrl);

    if (browserOpened) {
        console.log('✓ Browser opened\n');
        console.log('Complete authentication in your browser window.');
    } else {
        console.log('Could not open browser automatically.');
    }

    // I changed this to always show the URL because we got a report from
    // someone running happy inside a devcontainer that they saw the
    // "Complete authentication in your browser window." but nothing opened.
    // https://github.com/slopus/happy/issues/19
    console.log('\nIf the browser did not open, please copy and paste this URL:');
    console.log(webUrl);
    console.log('');

    return await waitForAuthentication(request);
}

/**
 * Wait for the user's app to answer, then save credentials only if the
 * answer passes verifyPairingResponse. Stops after PAIRING_TIMEOUT_MS. A
 * reply that fails the check ends pairing: the server decides what comes
 * next, so polling on would only wait for another forged reply.
 */
async function waitForAuthentication(request: PairingRequest): Promise<Credentials | null> {
    process.stdout.write('Waiting for authentication');
    let dots = 0;
    let cancelled = false;
    const deadline = Date.now() + PAIRING_TIMEOUT_MS;

    // Handle Ctrl-C during waiting
    const handleInterrupt = () => {
        cancelled = true;
        console.log('\n\nAuthentication cancelled.');
        process.exit(0);
    };

    process.on('SIGINT', handleInterrupt);

    try {
        while (!cancelled && Date.now() < deadline) {
            try {
                const response = await axios.post(`${configuration.serverUrl}/v1/auth/request`, {
                    publicKey: encodeBase64(request.keypair.publicKey),
                    supportsV2: true,
                    pairingVersion: 3
                }, {
                    headers: {
                        'X-Happy-Client': `cli/${configuration.currentCliVersion}`
                    }
                });
                if (response.data.state === 'authorized') {
                    const verified = verifyPairingResponse(String(response.data.response), request.keypair.secretKey, request.pairingSecret);
                    if (!verified.ok) {
                        logger.debug(`[AUTH] Pairing reply rejected: ${verified.reason}`);
                        console.log('\n\nPairing failed: the reply did not come from your Happy app.');
                        console.log('Your server or network may be tampering with the pairing. Nothing was saved.');
                        return null;
                    }
                    const credentials = {
                        publicKey: verified.contentPublicKey,
                        machineKey: new Uint8Array(randomBytes(32)),
                        token: response.data.token as string
                    };
                    await writeCredentialsDataKey(credentials);
                    console.log('\n\n✓ Authentication successful\n');
                    return {
                        encryption: {
                            type: 'dataKey',
                            publicKey: credentials.publicKey,
                            machineKey: credentials.machineKey
                        },
                        token: credentials.token
                    };
                }
            } catch (error) {
                console.log('\n\nFailed to check authentication status. Please try again.');
                return null;
            }

            // Animate waiting dots
            process.stdout.write('\rWaiting for authentication' + '.'.repeat((dots % 3) + 1) + '   ');
            dots++;

            await delay(1000);
        }
    } finally {
        process.off('SIGINT', handleInterrupt);
    }

    console.log('\n\nNo reply. If scanning did nothing, your Happy app is too old: update it,');
    console.log('or run `happy auth login` and choose Web.');
    return null;
}


/**
 * Ensure authentication and machine setup
 * This replaces the onboarding flow and ensures everything is ready
 */
export async function authAndSetupMachineIfNeeded(): Promise<{
    credentials: Credentials;
    machineId: string;
}> {
    logger.debug('[AUTH] Starting auth and machine setup...');

    // Step 1: Handle authentication
    let credentials = await readCredentials();
    let newAuth = false;

    if (!credentials) {
        logger.debug('[AUTH] No credentials found, starting authentication flow...');
        const authResult = await doAuth();
        if (!authResult) {
            throw new Error('Authentication failed or was cancelled');
        }
        credentials = authResult;
        newAuth = true;
    } else {
        logger.debug('[AUTH] Using existing credentials');
    }

    // Make sure we have a machine ID
    // Server machine entity will be created either by the daemon or by the CLI
    const settings = await updateSettings(async s => {
        if (newAuth || !s.machineId) {
            return {
                ...s,
                machineId: randomUUID()
            };
        }
        return s;
    });

    logger.debug(`[AUTH] Machine ID: ${settings.machineId}`);

    return { credentials, machineId: settings.machineId! };
}