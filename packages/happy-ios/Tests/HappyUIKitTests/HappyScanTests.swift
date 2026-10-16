#if canImport(UIKit)
import Foundation
import HappyCore
import HappyStore
@testable import HappyUI
import HappyWire
import UIKit
import XCTest

private struct NoNetwork: HTTPTransport {
    func send(_ request: HTTPRequest) async throws -> HTTPResponse {
        throw URLError(.notConnectedToInternet)
    }
}

private struct NoSockets: WebSocketConnector {
    func connect(to url: URL) async throws -> WebSocketConnection {
        throw URLError(.notConnectedToInternet)
    }
}

/// Both scans Steve used, Link New Device (`.connect`) and Add Account
/// (`.addAccount`), with every kind of code: each one does something the
/// person can see. Link New Device used to drop a computer's code and Pair
/// computer another device's, without a word. A computer's code, of either
/// form, first asks Connect Terminal, as happy-app does.
@MainActor
final class HappyScanTests: XCTestCase {
    private let key = Data(repeating: 9, count: 32)

    private func signedIn() async throws -> AccountController {
        let controller = AccountController(
            serverConfig: ServerConfig(storage: InMemoryKeyValueStore()),
            clientID: "ios/test",
            credentialStore: InMemoryCredentialStore(),
            storeDirectory: nil,
            rnServerImport: { .confirmed(ServerConfig.defaultServerURL) },
            transport: NoNetwork(),
            connector: NoSockets()
        )
        try await controller.signIn(Credentials(token: "t", secret: Data(repeating: 1, count: 32)))
        return controller
    }

    private func screens() -> (UIWindow, UINavigationController) {
        let navigation = UINavigationController(rootViewController: UIViewController())
        let window = UIWindow(frame: CGRect(x: 0, y: 0, width: 393, height: 852))
        window.rootViewController = navigation
        window.isHidden = false
        navigation.view.layoutIfNeeded()
        return (window, navigation)
    }

    private func until(_ condition: () -> Bool) async throws -> Bool {
        for _ in 0..<500 where !condition() {
            try await Task.sleep(for: .milliseconds(10))
        }
        return condition()
    }

    private func direct() throws -> String {
        let bundle: [String: Any] = ["v": 1, "a": "tcAddress", "p": 24781, "t": CanonicalBase64URL.encode(Data(repeating: 3, count: 32)), "n": "Mac", "e": 2_000_000_000_000.0]
        return PairingLink.prefix + CanonicalBase64URL.encode(try JSONSerialization.data(withJSONObject: bundle))
    }

    /// What the screen shows after `text` was opened: an alert's title and
    /// message, or the screen pushed. A Connect Terminal question is
    /// answered Reject, and the scan must then end: accepting is in
    /// `HostedLegacyTerminalCodeTests`, where a real scene lets the next
    /// alert show.
    private func shown(_ text: String, _ intent: ScanIntent, context: AppContext) async throws -> String {
        let (window, navigation) = screens()
        defer { window.isHidden = true }
        let host = try XCTUnwrap(navigation.topViewController)
        let task = Task { await HappyScan.open(text, intent: intent, context: context, on: host, start: .scan) }
        let visible = try await until { navigation.presentedViewController is UIAlertController || navigation.viewControllers.count > 1 }
        guard visible else {
            task.cancel()
            return "nothing"
        }
        if let alert = navigation.presentedViewController as? UIAlertController {
            if alert.title == Strings.Terminal.connectTerminal {
                try reject(alert)
                let result = await task.value
                XCTAssertEqual(result, .ended, "a rejected request went on")
            }
            return "\(alert.title ?? "") | \(alert.message ?? "")"
        }
        task.cancel()
        return String(describing: type(of: navigation.topViewController!))
    }

    /// Answers the question Reject, as its button would. `UIAlertAction`
    /// keeps its handler private, so a test reaches it by key; a test only.
    private func reject(_ alert: UIAlertController) throws {
        XCTAssertEqual(alert.actions.first { $0.style != .cancel }?.title, Strings.Terminal.acceptConnection)
        let action = try XCTUnwrap(alert.actions.first { $0.style == .cancel }, "no Reject")
        XCTAssertEqual(action.title, Strings.Terminal.reject)
        typealias Handler = @convention(block) (UIAlertAction) -> Void
        let handler = try XCTUnwrap(action.value(forKey: "handler") as AnyObject?, "Reject has no handler")
        unsafeBitCast(handler, to: Handler.self)(action)
    }

    func testEveryCodeFromEitherScanShowsSomething() async throws {
        let controller = try await signedIn()
        let context = AppContext(account: controller, variant: .development, version: "test")
        let keyText = CanonicalBase64URL.encode(key)
        let terminal = "happy://terminal?" + keyText
        let terminalV3 = "happy://pair/terminal?key=\(keyText)&s=\(CanonicalBase64URL.encode(Data(repeating: 4, count: 32)))"
        let account = "happy:///account?" + keyText
        let agentPairingCode = try direct()

        for intent in [ScanIntent.connect, .addAccount] {
            for text in [terminal, terminalV3, account, agentPairingCode, "happy://terminal?xx", "happy://pair/terminal?key=\(keyText)", "happy:///account?xx", "happy://direct?bad", "garbage", "https://example.com"] {
                let result = try await shown(text, intent, context: context)
                XCTAssertNotEqual(result, "nothing", "\(intent) \(text.prefix(20)) showed nothing")
            }
        }

        // A computer's code, either form, from either scan, asks first, and
        // a Reject ends it (`shown`).
        let question = "\(Strings.Terminal.connectTerminal) | \(Strings.Terminal.terminalRequestDescription)"
        for intent in [ScanIntent.connect, .addAccount] {
            for text in [terminal, terminalV3] {
                let asked = try await shown(text, intent, context: context)
                XCTAssertEqual(asked, question, "\(intent) \(text.prefix(22))")
            }
        }

        // What the others say.
        let linkDevice = try await shown(account, .connect, context: context)
        XCTAssertEqual(linkDevice, "\(Strings.Common.error) | \(Strings.Modals.failedToLinkDevice)")
        let garbage = try await shown("garbage", .connect, context: context)
        XCTAssertEqual(garbage, "\(Strings.Scan.notHappyTitle) | \(Strings.Scan.notHappy)")
        let broken = try await shown("happy://terminal?xx", .addAccount, context: context)
        XCTAssertEqual(broken, "\(Strings.Common.error) | \(Strings.Modals.invalidAuthUrl)")
        // A v3 code without its secret is broken, never an older code.
        let brokenV3 = try await shown("happy://pair/terminal?key=\(keyText)", .connect, context: context)
        XCTAssertEqual(brokenV3, "\(Strings.Common.error) | \(Strings.Modals.invalidAuthUrl)")
        await controller.signOut()
    }
}
#endif
