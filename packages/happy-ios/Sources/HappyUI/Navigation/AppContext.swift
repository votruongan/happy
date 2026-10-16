#if canImport(UIKit)
import HappyCore
import HappyWire
import UIKit

/// What every screen needs: the account and facts about this build.
@MainActor
public final class AppContext {
    public let account: AccountController
    public let variant: AppVariant
    public let version: String

    public init(account: AccountController, variant: AppVariant, version: String) {
        self.account = account
        self.variant = variant
        self.version = version
    }

    /// The custom server's host (and port), shown under the title; nil on
    /// the default server.
    var customServerHost: String? {
        account.serverConfig.isCustomServer ? account.serverConfig.displayHost : nil
    }
}

/// Scanning and answering pairing codes: connecting a terminal
/// (useConnectTerminal.ts) and linking another device (useConnectAccount.ts).
@MainActor
enum PairingFlow {
    enum Kind {
        case terminal
        case account

        /// The codes a scan of this kind keeps: either terminal link form,
        /// or the account link.
        func accepts(_ text: String) -> Bool {
            switch self {
            case .terminal: PairingLink.hasTerminalPrefix(text)
            case .account: text.trimmingCharacters(in: .whitespacesAndNewlines).hasPrefix(PairingLink.accountPrefix)
            }
        }

        func matches(_ link: PairingLink) -> Bool {
            link.isTerminal == (self == .terminal)
        }
    }

    enum Outcome: Equatable {
        case approved
        /// Not a pairing link of the expected kind.
        case invalidLink
        /// A terminal that only speaks auth v1.
        case terminalNeedsUpdate
        /// The terminal's request was already answered by someone else.
        case terminalAlreadyConnected
        case failed
    }

    /// Presents the camera and returns the first code of `kind` it reads;
    /// nil when closed. Other codes are ignored, as happy-app's scanner
    /// ignores them.
    static func scan(_ kind: Kind, from controller: UIViewController) async -> String? {
        await withCheckedContinuation { continuation in
            let scanner = QRScannerViewController()
            scanner.accepts = { kind.accepts($0) }
            scanner.onFinish = { continuation.resume(returning: $0) }
            controller.present(scanner, animated: true)
        }
    }

    /// Asks the person before a scanned, pasted or opened link is answered
    /// (useConnectTerminal.ts confirmAndProcessAuthUrl, AppCoordinator.open):
    /// a link can come from anywhere. True when they accept. A link that is
    /// not a valid one of `kind` gets the invalid-link alert instead, and
    /// false.
    static func confirm(_ text: String, kind: Kind, on controller: UIViewController) async -> Bool {
        guard let link = PairingLink(text), kind.matches(link) else {
            report(.invalidLink, kind: kind, on: controller)
            return false
        }
        switch kind {
        case .terminal:
            return await Alerts.confirm(
                Strings.Terminal.connectTerminal,
                Strings.Terminal.terminalRequestDescription,
                confirmTitle: Strings.Terminal.acceptConnection,
                cancelTitle: Strings.Terminal.reject,
                on: controller
            )
        case .account:
            return await Alerts.confirm(Strings.SettingsAccount.linkNewDevice, nil, confirmTitle: Strings.Common.continueAction, on: controller)
        }
    }

    /// Approves a scanned or pasted link of the expected kind. Callers ask
    /// with `confirm` first, unless the screen itself already asked.
    static func approve(_ text: String, expecting kind: Kind, session: AccountSession) async -> Outcome {
        guard let link = PairingLink(text), kind.matches(link) else {
            return .invalidLink
        }
        do {
            _ = try await session.pairing.approve(link)
            return .approved
        } catch PairingError.terminalNeedsUpdate {
            return .terminalNeedsUpdate
        } catch PairingError.terminalAlreadyConnected {
            return .terminalAlreadyConnected
        } catch {
            return .failed
        }
    }

    /// What happy-app tells the person. A connected terminal is felt, not
    /// announced: the computer turns up on screen. A linked device and every
    /// failure get an alert.
    static func report(_ outcome: Outcome, kind: Kind, on controller: UIViewController) {
        switch (outcome, kind) {
        case (.approved, .terminal):
            UINotificationFeedbackGenerator().notificationOccurred(.success)
        case (.approved, .account):
            Alerts.show(Strings.Common.success, Strings.Modals.deviceLinkedSuccessfully, on: controller)
        case (.invalidLink, _):
            Alerts.show(Strings.Common.error, Strings.Modals.invalidAuthUrl, on: controller)
        case (.terminalNeedsUpdate, _):
            Alerts.show(Strings.Common.error, Strings.Modals.terminalNeedsUpdate, on: controller)
        case (.terminalAlreadyConnected, _):
            Alerts.show(Strings.Terminal.alreadyConnectedTitle, Strings.Terminal.alreadyConnectedMessage, on: controller)
        case (.failed, .terminal):
            Alerts.show(Strings.Common.error, Strings.Modals.failedToConnectTerminal, on: controller)
        case (.failed, .account):
            Alerts.show(Strings.Common.error, Strings.Modals.failedToLinkDevice, on: controller)
        }
    }
}

extension UIViewController {
    /// A gear in the navigation bar.
    func settingsBarButton(action: Selector, label: String = Strings.Onboarding.settingsTitle) -> UIBarButtonItem {
        // HomeHeader.tsx: settings-outline at 22.
        let item = UIBarButtonItem(image: .icon(.ionicons("settings-outline"), size: 22), style: .plain, target: self, action: action)
        item.accessibilityLabel = label
        return item
    }

    /// happy-app's stack shows "Back" on the screens pushed from here.
    func showsBackTitle() {
        navigationItem.backButtonDisplayMode = .default
        navigationItem.backButtonTitle = Strings.Common.back
    }
}
#endif
