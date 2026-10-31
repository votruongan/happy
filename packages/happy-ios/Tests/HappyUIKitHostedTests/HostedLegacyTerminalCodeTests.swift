#if canImport(UIKit)
import Foundation
import HappyCore
import HappyCrypto
import HappyStore
@testable import HappyUI
import HappyWire
import UIKit
import XCTest

private struct NoSockets: WebSocketConnector {
    func connect(to url: URL) async throws -> WebSocketConnection {
        throw URLError(.notConnectedToInternet)
    }
}

private struct Unreachable: AgentTransport {
    func request(method: String, path: String, credential: String, body: Data?, headers: [String: String]) async throws -> HTTP1Response {
        throw URLError(.cannotConnectToHost)
    }
    func stream(path: String, credential: String, headers: [String: String]) async throws -> HTTP1Stream {
        throw URLError(.cannotConnectToHost)
    }
    func reset() async {}
    func close() async {}
}

/// The relay's auth routes as happy-server answers them: the query read
/// the way fastify reads it ("+" is a space) and the key decoded strictly,
/// so a mangled key is a 500. Nothing else answers.
private final class Relay: HTTPTransport, @unchecked Sendable {
    private let lock = NSLock()
    private let terminal: Data
    private var answered: [Data: Data] = [:]

    init(terminal: Data) { self.terminal = terminal }

    func answer(for key: Data) -> Data? { lock.withLock { answered[key] } }

    func send(_ request: HTTPRequest) async throws -> HTTPResponse {
        switch "\(request.method) \(request.url.path)" {
        case "POST /v1/auth":
            return HTTPResponse(status: 200, body: Data(#"{"success":true,"token":"token-\#(UUID().uuidString)"}"#.utf8))
        case "GET /v1/auth/request/status":
            let raw = request.url.query(percentEncoded: true) ?? ""
            let value = raw.split(separator: "&").first { $0.hasPrefix("publicKey=") }
                .map { String($0.dropFirst("publicKey=".count)).replacingOccurrences(of: "+", with: " ").removingPercentEncoding ?? "" }
            guard let key = value.flatMap({ Data(base64Encoded: $0) }) else {
                return HTTPResponse(status: 500, body: Data(#"{"message":"Base64Coder: incorrect characters for decoding"}"#.utf8))
            }
            let status = key != terminal ? "not_found" : (answer(for: key) == nil ? "pending" : "authorized")
            return HTTPResponse(status: 200, body: Data(#"{"status":"\#(status)","supportsV2":true}"#.utf8))
        case "POST /v1/auth/response":
            let body = try JSONSerialization.jsonObject(with: request.body ?? Data()) as? [String: String]
            guard let key = body?["publicKey"].flatMap({ Data(base64Encoded: $0) }),
                  let response = body?["response"].flatMap({ Data(base64Encoded: $0) }) else { return HTTPResponse(status: 400, body: Data()) }
            lock.withLock { answered[key] = response }
            return HTTPResponse(status: 200, body: Data(#"{"success":true}"#.utf8))
        default:
            throw URLError(.notConnectedToInternet)
        }
    }
}

/// Add Agent, then a computer's `happy://terminal?` code, in the app's own
/// window: once the person accepts Connect Terminal, a new Happy account
/// every time, whatever is here already. The computer gets it, the window
/// becomes its home, settings (when open) turns to it, and the person is
/// told; the accounts there were stay. A current CLI's
/// `happy://pair/terminal?` code gets the same, with its pairing secret in
/// the reply. The camera can't open in the test host (no
/// NSCameraUsageDescription), so the code goes in where the scanner hands
/// it over, `HappyScan.open`.
@MainActor
final class HostedLegacyTerminalCodeTests: XCTestCase {
    private enum Here { case nothing, happyAccount, agentConnection }

    /// A computer's key whose base64 has a "+", as about half do.
    private func terminal() throws -> BoxKeyPair {
        var seed: UInt8 = 0
        while true {
            let pair = try BoxKeyPair(secretKey: Data(repeating: seed, count: 32))
            if pair.publicKey.base64EncodedString().contains("+") { return pair }
            seed += 1
        }
    }

    private func stack(in window: UIWindow) -> UINavigationController? {
        var queue = [window.rootViewController].compactMap { $0 }
        while !queue.isEmpty {
            let next = queue.removeFirst()
            if let navigation = next as? UINavigationController { return navigation }
            queue += next.children
        }
        return nil
    }

    private func until(_ seconds: Double = 5, _ condition: () -> Bool) async throws -> Bool {
        let deadline = ContinuousClock.now + .milliseconds(Int(seconds * 1000))
        while !condition(), ContinuousClock.now < deadline { try await Task.sleep(for: .milliseconds(20)) }
        return condition()
    }

    /// Answers the Connect Terminal question once it shows: Accept
    /// Connection, or Reject. `UIAlertAction` keeps its handler private, so
    /// a test reaches it by key; a test only.
    private func answer(in window: UIWindow, accept: Bool = true) async throws {
        var question: UIAlertController? { window.rootViewController?.presentedViewController as? UIAlertController }
        let asked = try await until { question.map { $0.title == Strings.Terminal.connectTerminal && !$0.isBeingPresented } ?? false }
        XCTAssertTrue(asked, "Connect Terminal never asked; presented: \(String(describing: window.rootViewController?.presentedViewController))")
        let alert = try XCTUnwrap(question)
        XCTAssertEqual(alert.message, Strings.Terminal.terminalRequestDescription)
        let acceptAction = try XCTUnwrap(alert.actions.first { $0.title == Strings.Terminal.acceptConnection }, "no Accept Connection")
        let rejectAction = try XCTUnwrap(alert.actions.first { $0.title == Strings.Terminal.reject && $0.style == .cancel }, "no Reject")
        let action = accept ? acceptAction : rejectAction
        typealias Handler = @convention(block) (UIAlertAction) -> Void
        let handler = try XCTUnwrap(action.value(forKey: "handler") as AnyObject?, "\(action.title ?? "") has no handler")
        alert.dismiss(animated: false) {
            unsafeBitCast(handler, to: Handler.self)(action)
        }
    }

    private func run(_ here: Here, pairingSecret: Data? = nil) async throws {
        let computer = try terminal()
        let relay = Relay(terminal: computer.publicKey)
        let account = AccountController(
            serverConfig: ServerConfig(storage: InMemoryKeyValueStore()), clientID: "ios/test",
            credentialStore: InMemoryCredentialStore(), storeDirectory: nil,
            agentTransport: { _ in Unreachable() },
            rnServerImport: { .confirmed(ServerConfig.defaultServerURL) },
            transport: relay, connector: NoSockets())
        await account.agentConnections.setForeground(false)
        await account.restore()
        switch here {
        case .nothing: break
        case .happyAccount:
            try await account.signIn(Credentials(token: "existing", secret: Data(repeating: 7, count: 32)))
        case .agentConnection:
            try await account.addAgentConnection(JSONDecoder().decode(AgentConnectionCredentials.self, from: Data(#"{"address":"terminal-code-test","port":1,"deviceID":"\#(UUID().uuidString)","deviceToken":"token"}"#.utf8)), name: "Mac")
            let id = try XCTUnwrap(account.agentConnections.activeID)
            addTeardownBlock { @MainActor in Session.forget(id) }
        }
        let before = account.accounts
        let context = AppContext(account: account, variant: .preview, version: "test")

        let scene = try await hostedActiveScene()
        let hostWindow = scene.keyWindow
        let window = UIWindow(windowScene: scene)
        let coordinator = AppCoordinator(window: window, context: context)
        coordinator.start()
        addTeardownBlock { @MainActor in
            window.rootViewController?.presentedViewController?.dismiss(animated: false)
            window.isHidden = true
            hostWindow?.makeKey()
        }
        let navigation = try XCTUnwrap(stack(in: window))
        let firstRoot = try await until {
            switch here {
            case .nothing: navigation.viewControllers.first is StartViewController
            case .happyAccount: navigation.viewControllers.first is LegacyHomeViewController
            case .agentConnection: navigation.viewControllers.first is AgentHomeViewController
            }
        }
        XCTAssertTrue(firstRoot, "\(here): the window never showed what's here: \(navigation.viewControllers)")
        // Restore, which start() runs again, holds the account controller.
        try await Task.sleep(for: .milliseconds(500))

        // With something here, Add Agent is on Settings; with nothing, on Start.
        var settings: SettingsViewController?
        if here != .nothing {
            let page = SettingsViewController(context: context, computer: nil)
            navigation.pushViewController(page, animated: false)
            page.view.layoutIfNeeded()
            settings = page
        }
        let host = try XCTUnwrap(navigation.topViewController)
        let code = LegacyPairingLink.terminalLink(publicKey: computer.publicKey, pairingSecret: pairingSecret).urlString
        let scan = Task { await HappyScan.open(code, intent: .addAccount, context: context, on: host, start: .scan) }
        try await answer(in: window)
        let result = await scan.value
        XCTAssertEqual(result, .accountAdded, "\(here)")

        // One account more, the new one, active; the others as they were.
        let session = try XCTUnwrap(account.session, "\(here): no account is active")
        let newID = session.keys.anonID
        XCTAssertEqual(account.accounts.count, before.count + 1, "\(here)")
        XCTAssertEqual(Set(account.accounts.map(\.id)), Set(before.map(\.id) + [newID]), "\(here)")
        XCTAssertEqual(account.accounts.filter(\.isActive).map(\.id), [newID], "\(here)")
        XCTAssertNil(account.agentConnections.activeID, "\(here)")

        // The computer has the new account's content key.
        let response = try XCTUnwrap(relay.answer(for: computer.publicKey), "\(here): the computer was never answered")
        let opened = try XCTUnwrap(Box.openAnonymous(response, recipientSecretKey: computer.secretKey))
        if let pairingSecret {
            XCTAssertEqual(opened, Data([3]) + session.keys.contentKeyPair.publicKey + pairingSecret, "\(here)")
        } else {
            XCTAssertEqual(opened, Data([0]) + session.keys.contentKeyPair.publicKey, "\(here)")
        }

        // The window is the new account's home, the person is told, and
        // settings, still on top, shows the new account ticked.
        let home = navigation.viewControllers.first as? LegacyHomeViewController
        XCTAssertNotNil(home, "\(here): the root is \(String(describing: navigation.viewControllers.first))")
        let told = try await until { (window.rootViewController?.presentedViewController as? UIAlertController)?.message == Strings.Modals.terminalConnectedSuccessfully }
        XCTAssertTrue(told, "\(here): no success alert, presented: \(String(describing: window.rootViewController?.presentedViewController))")
        if let settings {
            XCTAssertTrue(navigation.topViewController === settings, "\(here): settings went away")
            XCTAssertEqual(settings.shownProfileID, newID, "\(here): settings still shows the old account")
            XCTAssertEqual(settings.tickedRowIDs, ["account:\(newID)"], "\(here)")
            XCTAssertEqual(settings.shownRowIDs.first?.filter { $0.hasPrefix("account:") }.count, before.count + 1, "\(here): \(settings.shownRowIDs)")
        }

        // Named after the first computer paired with it, once that turns
        // up; an agent until then, never "Legacy Account" or "Happy account".
        let page = settings ?? {
            let page = SettingsViewController(context: context, computer: nil)
            navigation.pushViewController(page, animated: false)
            page.view.layoutIfNeeded()
            return page
        }()
        XCTAssertEqual(title(of: newID, in: page), Strings.agentConnection, "\(here)")
        try session.store.upsertMachine(MachineRecord(id: "mac", seq: 0, createdAt: 1, updatedAt: 1, active: true, activeAt: 1,
            metadataVersion: 1, metadataCipher: "c", metadata: .object(["host": .string("mbp.local"), "displayName": .string("Steve’s MacBook")]),
            daemonStateVersion: 0, daemonStateCipher: nil, daemonState: nil, dataKeyCipher: "k", decryptable: true))
        let named = try await until { self.title(of: newID, in: page) == "Steve’s MacBook" }
        XCTAssertTrue(named, "\(here): still \(String(describing: title(of: newID, in: page)))")
        XCTAssertEqual(account.accounts.first { $0.id == newID }?.shownName, "Steve’s MacBook")
        for old in before where !old.isAgentConnection && old.resolvedName == nil {
            XCTAssertEqual(title(of: old.id, in: page), Strings.legacyAccount, "\(here)")
        }

        // Its Backup & Restore offers no key to show and no device to
        // link, but still restores another; Settings still signs it out.
        let backup = BackupSettingsViewController(context: context, session: session)
        backup.loadViewIfNeeded()
        XCTAssertFalse(backup.isLegacy, "\(here)")
        let rows = backup.shownRowIDs.joined()
        XCTAssertFalse(rows.contains("secret-key"), "\(here): \(rows)")
        XCTAssertFalse(rows.contains("link-device"), "\(here): \(rows)")
        XCTAssertEqual(Array(rows), ["no-key", "restore"], "\(here)")
        backup.tapRow("no-key")
        XCTAssertFalse(backup.shownRowIDs.joined().contains("secret-key-text"), "\(here): the key showed")
        XCTAssertNotNil(page.shownRow("sign-out"), "\(here)")
        withExtendedLifetime(coordinator) {}
    }

    private func title(of id: String, in settings: SettingsViewController) -> String? {
        zip(settings.shownRowIDs.joined(), settings.shownRowTitles.joined()).first { $0.0 == "account:\(id)" }?.1
    }

    /// A legacy account's Backup & Restore keeps its key and Link New Device.
    func testALegacyAccountKeepsItsKey() async throws {
        let account = AccountController(
            serverConfig: ServerConfig(storage: InMemoryKeyValueStore()), clientID: "ios/test",
            credentialStore: InMemoryCredentialStore(), storeDirectory: nil,
            rnServerImport: { .confirmed(ServerConfig.defaultServerURL) },
            transport: Relay(terminal: Data()), connector: NoSockets())
        try await account.signIn(Credentials(token: "existing", secret: Data(repeating: 7, count: 32)))
        let context = AppContext(account: account, variant: .preview, version: "test")
        let page = BackupSettingsViewController(context: context, session: try XCTUnwrap(account.session))
        page.loadViewIfNeeded()
        XCTAssertTrue(page.isLegacy)
        XCTAssertEqual(page.shownRowIDs, [["secret-key"], ["link-device"], ["restore"]])
        XCTAssertEqual(account.accounts.first?.shownName, Strings.legacyAccount)
        await account.signOut()
    }

    /// Pair computer with a computer's code, signed in: nothing reaches the
    /// computer until the person accepts Connect Terminal, Reject sends
    /// nothing, a current CLI's reply carries its pairing secret, and the
    /// same code again is the "Terminal already connected" warning.
    func testConnectingAComputerAsksFirst() async throws {
        let computer = try terminal()
        let secret = Data(repeating: 6, count: 32)
        let relay = Relay(terminal: computer.publicKey)
        let account = AccountController(
            serverConfig: ServerConfig(storage: InMemoryKeyValueStore()), clientID: "ios/test",
            credentialStore: InMemoryCredentialStore(), storeDirectory: nil,
            agentTransport: { _ in Unreachable() },
            rnServerImport: { .confirmed(ServerConfig.defaultServerURL) },
            transport: relay, connector: NoSockets())
        await account.agentConnections.setForeground(false)
        await account.restore()
        try await account.signIn(Credentials(token: "existing", secret: Data(repeating: 7, count: 32)))
        let session = try XCTUnwrap(account.session)
        let context = AppContext(account: account, variant: .preview, version: "test")
        let scene = try await hostedActiveScene()
        let hostWindow = scene.keyWindow
        let window = hostedKeyWindow(in: scene)
        addTeardownBlock { @MainActor in
            window.rootViewController?.presentedViewController?.dismiss(animated: false)
            window.isHidden = true
            hostWindow?.makeKey()
        }
        let host = try XCTUnwrap(window.rootViewController)
        let code = LegacyPairingLink.terminalV3(publicKey: computer.publicKey, pairingSecret: secret).urlString
        var presented: UIAlertController? { window.rootViewController?.presentedViewController as? UIAlertController }

        let rejected = Task { await HappyScan.open(code, intent: .connect, context: context, on: host, start: .scan) }
        try await answer(in: window, accept: false)
        let rejectedResult = await rejected.value
        XCTAssertEqual(rejectedResult, .ended)
        XCTAssertNil(relay.answer(for: computer.publicKey), "a rejected request was answered")
        let quiet = try await until { presented == nil }
        XCTAssertTrue(quiet, "something showed after Reject: \(String(describing: presented?.title))")

        let accepted = Task { await HappyScan.open(code, intent: .connect, context: context, on: host, start: .scan) }
        try await answer(in: window)
        let acceptedResult = await accepted.value
        XCTAssertEqual(acceptedResult, .computerConnected)
        let response = try XCTUnwrap(relay.answer(for: computer.publicKey), "the computer was never answered")
        let opened = try XCTUnwrap(Box.openAnonymous(response, recipientSecretKey: computer.secretKey))
        XCTAssertEqual(opened, Data([3]) + session.keys.contentKeyPair.publicKey + secret)
        XCTAssertNil(opened.range(of: session.keys.secret), "the master secret must not reach a terminal")
        XCTAssertEqual(account.session?.keys.anonID, session.keys.anonID, "connecting a computer changed the account")
        let told = try await until { presented?.message == Strings.Modals.terminalConnectedSuccessfully && presented?.isBeingPresented == false }
        XCTAssertTrue(told, "no success alert, presented: \(String(describing: presented?.title))")
        presented?.dismiss(animated: false)
        let dismissed = try await until { presented == nil }
        XCTAssertTrue(dismissed)

        let again = Task { await HappyScan.open(code, intent: .connect, context: context, on: host, start: .scan) }
        try await answer(in: window)
        let againResult = await again.value
        XCTAssertEqual(againResult, .ended)
        let warned = try await until { presented?.title == Strings.Terminal.alreadyConnectedTitle }
        XCTAssertTrue(warned, "no warning, presented: \(String(describing: presented?.title))")
        XCTAssertEqual(presented?.message, Strings.Terminal.alreadyConnectedMessage)
    }

    func testWithNothingHere() async throws { try await run(.nothing) }
    func testAV3CodeBesideAHappyAccount() async throws { try await run(.happyAccount, pairingSecret: Data(repeating: 6, count: 32)) }
    func testBesideAHappyAccount() async throws { try await run(.happyAccount) }
    func testBesideAnAgentConnection() async throws { try await run(.agentConnection) }
}
#endif
