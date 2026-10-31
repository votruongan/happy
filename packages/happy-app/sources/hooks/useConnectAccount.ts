import * as React from 'react';
import { Platform } from 'react-native';
import { CameraView } from 'expo-camera';
import { useAuth } from '@/auth/AuthContext';
import { decodeBase64 } from '@/encryption/base64';
import { encryptBox } from '@/encryption/libsodium';
import { AccountLinkAlreadyAnsweredError, authAccountApprove } from '@/auth/authAccountApprove';
import { buildAccountPairingPayload, isAccountPairingUrl, isLegacyAccountUrl, parseAccountPairingUrl } from '@/auth/accountPairing';
import { useCheckScannerPermissions } from '@/hooks/useCheckCameraPermissions';
import { Modal } from '@/modal';
import { t } from '@/text';

interface UseConnectAccountOptions {
    onSuccess?: () => void;
    onError?: (error: any) => void;
}

/**
 * Links a new device (phone, web, desktop) to this account by scanning the
 * QR code that it shows.
 *
 * The reply gives the new device the account master secret, so every link
 * asks the user first, also a camera scan. Only `happy://pair/account?...`
 * links are answered, and the reply carries the link's pairing secret (see
 * `auth/accountPairing.ts`). Older `happy:///account?<pk>` links get an
 * "update the other device" message and no reply.
 */
export function useConnectAccount(options?: UseConnectAccountOptions) {
    const auth = useAuth();
    const [isLoading, setIsLoading] = React.useState(false);
    const checkScannerPermissions = useCheckScannerPermissions();

    const processAuthUrl = React.useCallback(async (url: string) => {
        if (isLegacyAccountUrl(url)) {
            Modal.alert(t('common.error'), t('modals.linkDeviceOutdated'), [{ text: t('common.ok') }]);
            return false;
        }
        const link = parseAccountPairingUrl(url);
        if (!link) {
            Modal.alert(t('common.error'), t('modals.invalidAuthUrl'), [{ text: t('common.ok') }]);
            return false;
        }
        const accepted = await Modal.confirm(
            t('modals.linkDeviceConfirmTitle'),
            t('modals.linkDeviceConfirmMessage'),
            { confirmText: t('modals.linkDeviceConfirmButton'), destructive: true }
        );
        if (!accepted) {
            return false;
        }

        setIsLoading(true);
        try {
            const payload = buildAccountPairingPayload(link, decodeBase64(auth.credentials!.secret, 'base64url'));
            await authAccountApprove(auth.credentials!.token, link.publicKey, encryptBox(payload, link.publicKey));

            Modal.alert(t('common.success'), t('modals.deviceLinkedSuccessfully'), [
                { 
                    text: t('common.ok'), 
                    onPress: () => options?.onSuccess?.()
                }
            ]);
            return true;
        } catch (e) {
            if (e instanceof AccountLinkAlreadyAnsweredError) {
                // A security warning, not an ordinary failure.
                Modal.alert(t('modals.linkDeviceAlreadyAnsweredTitle'), t('modals.linkDeviceAlreadyAnsweredMessage'), [{ text: t('common.ok') }]);
                options?.onError?.(e);
                return false;
            }
            console.error(e);
            Modal.alert(t('common.error'), t('modals.failedToLinkDevice'), [{ text: t('common.ok') }]);
            options?.onError?.(e);
            return false;
        } finally {
            setIsLoading(false);
        }
    }, [auth.credentials, options]);

    const connectAccount = React.useCallback(async () => {
        if (await checkScannerPermissions()) {
            // Use camera scanner
            CameraView.launchScanner({
                barcodeTypes: ['qr']
            });
        } else {
            Modal.alert(t('common.error'), t('modals.cameraPermissionsRequiredToScanQr'), [{ text: t('common.ok') }]);
        }
    }, [checkScannerPermissions]);

    const connectWithUrl = React.useCallback(async (url: string) => {
        return await processAuthUrl(url);
    }, [processAuthUrl]);

    // Set up barcode scanner listener
    const isProcessingRef = React.useRef(false);
    React.useEffect(() => {
        if (CameraView.isModernBarcodeScannerAvailable) {
            const subscription = CameraView.onModernBarcodeScanned(async (event) => {
                if (isProcessingRef.current) return;
                if (isAccountPairingUrl(event.data) || isLegacyAccountUrl(event.data)) {
                    isProcessingRef.current = true;
                    try {
                        if (Platform.OS === 'ios') {
                            try {
                                await CameraView.dismissScanner();
                            } catch (e) {
                                console.warn('Failed to dismiss scanner', e);
                            }
                        }
                        await processAuthUrl(event.data);
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
    }, [processAuthUrl]);

    return {
        connectAccount,
        connectWithUrl,
        isLoading,
        processAuthUrl
    };
}
