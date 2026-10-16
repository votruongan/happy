import Foundation
import HappyCrypto
import HappyWire

public enum PairingOutcome: Equatable, Sendable {
    /// The terminal can now act for this account.
    case terminalConnected
    /// The other device received the account.
    case deviceLinked
}

public enum PairingError: Error, Equatable, Sendable {
    /// The terminal only speaks auth v1, which hands over the master secret.
    /// The iOS app supports the current protocol only, so the user has to
    /// update Happy on that computer.
    case terminalNeedsUpdate
    /// The terminal's request already has an answer this app did not send
    /// (status `authorized`, or 409 on the answer). Someone else may have
    /// connected the terminal, so it is a warning, never success.
    case terminalAlreadyConnected
    /// No such request: it expired, or the link is not a real one.
    case terminalNotFound
}

/// Answers QR codes scanned by a signed-in device: connecting a terminal
/// (`happy://pair/terminal?`, or `happy://terminal?` from older CLIs) or
/// linking another device (`happy:///account?`). Mirrors
/// useConnectTerminal.ts and useConnectAccount.ts.
public struct PairingService: Sendable {
    private let api: HappyAPI
    private let keys: AccountKeys
    private let random: RandomSource

    /// `api` must be signed in.
    public init(api: HappyAPI, keys: AccountKeys, random: RandomSource = SystemRandom()) {
        self.api = api
        self.keys = keys
        self.random = random
    }

    public func approve(_ link: PairingLink) async throws -> PairingOutcome {
        switch link {
        case .terminal(let publicKey):
            return try await connectTerminal(publicKey: publicKey, pairingSecret: nil)
        case .terminalV3(let publicKey, let pairingSecret):
            return try await connectTerminal(publicKey: publicKey, pairingSecret: pairingSecret)
        case .account(let publicKey):
            let response = try keys.accountLinkApproval(devicePublicKey: publicKey, random: random)
            try await api.approveAccountLink(publicKey: publicKey, response: response)
            return .deviceLinked
        }
    }

    /// The reply comes from the link alone (`AccountKeys.terminalApproval`).
    /// The server's `supportsV2` can only make this refuse, never change
    /// what is sent.
    private func connectTerminal(publicKey: Data, pairingSecret: Data?) async throws -> PairingOutcome {
        let status = try await api.terminalAuthStatus(publicKey: publicKey)
        switch status.status {
        case .notFound:
            throw PairingError.terminalNotFound
        case .authorized:
            throw PairingError.terminalAlreadyConnected
        case .pending:
            guard status.supportsV2 else { throw PairingError.terminalNeedsUpdate }
            let response = try keys.terminalApproval(terminalPublicKey: publicKey, pairingSecret: pairingSecret, random: random)
            do {
                try await api.approveTerminal(publicKey: publicKey, response: response)
            } catch APIError.http(status: 409, body: _) {
                // The server keeps only the first answer and turns any other away.
                throw PairingError.terminalAlreadyConnected
            }
            return .terminalConnected
        }
    }
}
