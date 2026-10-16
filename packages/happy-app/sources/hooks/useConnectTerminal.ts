import * as React from 'react';
import { Platform } from 'react-native';
import { CameraView } from 'expo-camera';
import { useAuth } from '@/auth/AuthContext';
import { encryptBox } from '@/encryption/libsodium';
import { authApprove, TerminalAlreadyAnsweredError } from '@/auth/authApprove';
import { buildTerminalPairingPayload, isTerminalPairingUrl, parseTerminalPairingUrl } from '@/auth/terminalPairing';
import { useCheckScannerPermissions } from '@/hooks/useCheckCameraPermissions';
import { Modal } from '@/modal';
import { t } from '@/text';
import { sync } from '@/sync/sync';
import { hapticsSuccess } from '@/components/haptics';

interface UseConnectTerminalOptions {
    onSuccess?: () => void;
    onError?: (error: any) => void;
}

// Several screens can have this hook mounted at once (a stack keeps the
// screens under the top one alive), and each of them listens for scans. Only
// the instance that opened the scanner handles what it reads, so one scan
// asks once and answers once.
let scannerOwner: object | null = null;

/**
 * Connects a terminal (CLI) to this account.
 *
 * `processAuthUrl` answers at once. Only screens that already showed the
 * request and got Accept call it. A camera scan or a pasted URL goes through
 * `connectWithUrl`, which first asks the user to accept the request.
 *
 * The reply comes from the link alone (see `auth/terminalPairing.ts`) and
 * never contains the account master secret.
 */
export function useConnectTerminal(options?: UseConnectTerminalOptions) {
    const auth = useAuth();
    const [isLoading, setIsLoading] = React.useState(false);
    const checkScannerPermissions = useCheckScannerPermissions();
    const ownerRef = React.useRef({});

    const processAuthUrl = React.useCallback(async (url: string) => {
        const link = parseTerminalPairingUrl(url);
        if (!link) {
            Modal.alert(t('common.error'), t('modals.invalidAuthUrl'), [{ text: t('common.ok') }]);
            return false;
        }

        setIsLoading(true);
        try {
            const payload = buildTerminalPairingPayload(link, sync.encryption.contentDataKey);
            await authApprove(auth.credentials!.token, link.publicKey, encryptBox(payload, link.publicKey));

            // People expect a scan to work, so success is felt, not announced:
            // the machine turns up in the list. Only a failure gets an alert.
            hapticsSuccess();
            options?.onSuccess?.();
            return true;
        } catch (e) {
            if (e instanceof TerminalAlreadyAnsweredError) {
                // A security warning, not an ordinary failure: always shown.
                Modal.alert(t('terminal.alreadyConnectedTitle'), t('terminal.alreadyConnectedMessage'), [{ text: t('common.ok') }]);
                options?.onError?.(e);
                return false;
            }
            console.error(e);
            // A caller that handles failures reports them in its own UI.
            if (options?.onError) {
                options.onError(e);
            } else {
                Modal.alert(t('common.error'), t('modals.failedToConnectTerminal'), [{ text: t('common.ok') }]);
            }
            return false;
        } finally {
            setIsLoading(false);
        }
    }, [auth.credentials, options]);

    const confirmAndProcessAuthUrl = React.useCallback(async (url: string) => {
        if (!parseTerminalPairingUrl(url)) {
            Modal.alert(t('common.error'), t('modals.invalidAuthUrl'), [{ text: t('common.ok') }]);
            return false;
        }
        const accepted = await Modal.confirm(
            t('terminal.connectTerminal'),
            t('terminal.terminalRequestDescription'),
            { confirmText: t('terminal.acceptConnection'), cancelText: t('terminal.reject') }
        );
        if (!accepted) {
            return false;
        }
        return await processAuthUrl(url);
    }, [processAuthUrl]);

    const connectTerminal = React.useCallback(async () => {
        if (await checkScannerPermissions()) {
            // Use camera scanner
            scannerOwner = ownerRef.current;
            CameraView.launchScanner({
                barcodeTypes: ['qr']
            });
        } else {
            Modal.alert(t('common.error'), t('modals.cameraPermissionsRequiredToConnectTerminal'), [{ text: t('common.ok') }]);
        }
    }, [checkScannerPermissions]);

    const connectWithUrl = React.useCallback(async (url: string) => {
        return await confirmAndProcessAuthUrl(url);
    }, [confirmAndProcessAuthUrl]);

    // The listener below re-subscribes when its callbacks change, so the
    // scanner is released here, on unmount only.
    React.useEffect(() => {
        const owner = ownerRef.current;
        return () => {
            if (scannerOwner === owner) {
                scannerOwner = null;
            }
        };
    }, []);

    // Set up barcode scanner listener
    const isProcessingRef = React.useRef(false);
    React.useEffect(() => {
        if (CameraView.isModernBarcodeScannerAvailable) {
            const owner = ownerRef.current;
            const subscription = CameraView.onModernBarcodeScanned(async (event) => {
                if (isProcessingRef.current) return;
                if (scannerOwner !== owner) return;
                if (isTerminalPairingUrl(event.data)) {
                    isProcessingRef.current = true;
                    scannerOwner = null;
                    try {
                        if (Platform.OS === 'ios') {
                            try {
                                await CameraView.dismissScanner();
                            } catch (e) {
                                console.warn('Failed to dismiss scanner', e);
                            }
                        }
                        await confirmAndProcessAuthUrl(event.data);
                    } finally {
                        isProcessingRef.current = false;
                    }
                }
            });
            return () => {
                subscription.remove();
                isProcessingRef.current = false;
                if (Platform.OS === 'ios') {
                    CameraView.dismissScanner().catch((e: unknown) => {
                        console.warn('Failed to dismiss scanner during cleanup', e);
                    });
                }
            };
        }
    }, [confirmAndProcessAuthUrl]);

    return {
        connectTerminal,
        connectWithUrl,
        isLoading,
        processAuthUrl
    };
}
