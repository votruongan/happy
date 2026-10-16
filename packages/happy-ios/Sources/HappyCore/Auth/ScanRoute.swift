import Foundation
import HappyWire

/// Where a scan started, which decides what a computer's code adds.
public enum ScanIntent: Equatable, Sendable {
    /// Connect something to the account in use: Link New Device, Pair
    /// computer.
    case connect
    /// Add an account beside the ones there are: a computer's code makes a
    /// new Happy account for it.
    case addAccount
}

/// What a scanned or pasted code leads to. Every code has a route, a
/// wrong one included: a scan never ends in silence.
public enum ScanRoute: Equatable, Sendable {
    /// Pair with the computer directly; it joins the accounts and opens.
    case connectAgent(PairingLink)
    /// Hand the computer the Happy account in use. `pairingSecret` is a
    /// current CLI's (`HappyCode.terminal`), and goes back in the reply.
    case connectComputer(publicKey: Data, pairingSecret: Data? = nil)
    /// Make a Happy account, add it beside the others, and hand it to the
    /// computer: when adding an account, or when there is none here yet.
    case newAccountForComputer(publicKey: Data, pairingSecret: Data? = nil)
    /// Hand the other device the Happy account in use.
    case linkDevice(publicKey: Data)
    case problem(ScanProblem)

    /// `hasAccount`: a Happy (relay) account is in use, not only a
    /// directly paired computer. `canShareAccount`: that account is a legacy
    /// one, whose secret may go to another device; one made for a computer
    /// never leaves it and this phone.
    public static func route(_ code: HappyCode, intent: ScanIntent, hasAccount: Bool, canShareAccount: Bool = true) -> ScanRoute {
        switch code {
        case .agentConnection(let link):
            return .connectAgent(link)
        case .terminal(let key, let secret):
            return hasAccount && intent == .connect
                ? .connectComputer(publicKey: key, pairingSecret: secret)
                : .newAccountForComputer(publicKey: key, pairingSecret: secret)
        case .account(let key):
            guard hasAccount else { return .problem(.deviceNeedsAccount) }
            return canShareAccount ? .linkDevice(publicKey: key) : .problem(.accountNotShareable)
        case .invalid(.terminal):
            return .problem(.invalidTerminal)
        case .invalid(.account):
            return .problem(.invalidAccount)
        case .invalid(.agentConnection(let error)):
            return .problem(.agentConnection(error))
        case .notHappy:
            return .problem(.notHappy)
        }
    }
}

extension ScanRoute {
    /// The terminal link a computer's route answers, in the form its code
    /// came in; nil for the other routes.
    public var terminalLink: LegacyPairingLink? {
        switch self {
        case .connectComputer(let key, let secret), .newAccountForComputer(let key, let secret):
            return .terminalLink(publicKey: key, pairingSecret: secret)
        case .connectAgent, .linkDevice, .problem:
            return nil
        }
    }
}

public enum ScanProblem: Equatable, Sendable {
    case notHappy
    case invalidTerminal
    case invalidAccount
    case agentConnection(PairingError)
    /// Another device's account link, with no Happy account here to give.
    case deviceNeedsAccount
    /// Another device's account link, while the account in use was made
    /// for a computer: its secret is never handed on.
    case accountNotShareable
}
