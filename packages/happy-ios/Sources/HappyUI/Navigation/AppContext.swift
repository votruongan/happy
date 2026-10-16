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

/// Asking about and answering relay pairing codes: connecting a terminal
/// (useConnectTerminal.ts) and linking another device (useConnectAccount.ts).
/// `HappyScan` reads and routes every code; this asks and answers.
@MainActor
enum LegacyPairingFlow {
    enum Kind {
        case terminal
        case account
    }

    enum Outcome: Equatable {
        case approved
        /// No such request: it was used already, or has expired. Nothing
        /// was sent.
        case notFound
        /// Not a pairing link of the expected kind.
        case invalidLink
        /// A terminal that only speaks auth v1.
        case terminalNeedsUpdate
        /// The terminal's request was already answered, not by this app:
        /// someone else may have connected it.
        case terminalAlreadyConnected
        case failed
    }

    /// Asks the person before a scanned, pasted or opened code is answered
    /// (useConnectTerminal.ts confirmAndProcessAuthUrl): a code can come
    /// from anywhere, and answering a terminal's hands it the account.
    /// True when they accept.
    static func confirm(_ kind: Kind, on controller: UIViewController) async -> Bool {
        switch kind {
        case .terminal:
            await Alerts.confirm(
                Strings.Terminal.connectTerminal,
                Strings.Terminal.terminalRequestDescription,
                confirmTitle: Strings.Terminal.acceptConnection,
                cancelTitle: Strings.Terminal.reject,
                on: controller
            )
        case .account:
            await Alerts.confirm(Strings.SettingsAccount.linkNewDevice, nil, confirmTitle: Strings.Common.continueAction, on: controller)
        }
    }

    /// Answers `link`. A terminal's is answered only once the person
    /// accepted it (`confirm`, which `HappyScan.open` asks).
    static func approve(_ link: LegacyPairingLink, session: AccountSession) async -> Outcome {
        do {
            _ = try await session.pairing.approve(link)
            return .approved
        } catch {
            return outcome(of: error)
        }
    }

    /// What an approval that threw tells the person.
    static func outcome(of error: Error) -> Outcome {
        switch error as? LegacyPairingError {
        case .terminalNeedsUpdate: .terminalNeedsUpdate
        case .terminalAlreadyConnected: .terminalAlreadyConnected
        case .terminalNotFound: .notFound
        case nil: .failed
        }
    }

    /// What happy-app tells the person. A connected terminal is felt, not
    /// announced: the computer turns up on screen. A linked device and every
    /// failure get an alert; an answered request gets the warning.
    static func report(_ outcome: Outcome, kind: Kind, on controller: UIViewController) {
        switch (outcome, kind) {
        case (.approved, .terminal):
            UINotificationFeedbackGenerator().notificationOccurred(.success)
        case (.approved, .account):
            Alerts.show(Strings.Common.success, Strings.Modals.deviceLinkedSuccessfully, on: controller)
        case (.notFound, _):
            Alerts.show(Strings.Scan.alreadyUsedTitle, Strings.Scan.alreadyUsed, on: controller)
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

    /// The screens pushed from here go back with the chevron alone, in its
    /// glass circle: never "Back" nor this screen's title. The shell's
    /// stack says the same of every screen (`TabletShellViewController`);
    /// this covers one pushed onto another stack.
    func minimalBackButton() {
        navigationItem.backButtonDisplayMode = .minimal
        navigationItem.backButtonTitle = nil
    }
}
#endif
