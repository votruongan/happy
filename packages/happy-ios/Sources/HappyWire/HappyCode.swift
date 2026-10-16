import Foundation

/// Whatever a scanner read or a person pasted, sorted into the codes Happy
/// makes. Every string lands in exactly one case, so a scan can always say
/// what it saw: nothing is dropped for being of the wrong kind.
///
/// The formats, from the code that draws them:
/// - `happy://pair/terminal?key=<key>&s=<secret>`: current CLIs (pairing
///   v3, happy-app auth/terminalPairing.ts).
/// - `happy://terminal?<key>`: older happy-cli (src/ui/auth.ts:102), Happy
///   Agent's "Link Mobile App" QR (the `authorization.data` of its Happy
///   integration), and the desktop app.
/// - `<webapp>/terminal/connect#key=<key>`: happy-cli's web sign-in
///   (src/api/webAuth.ts:11), when pasted; `#v=3&key=<key>&s=<secret>`
///   from current CLIs.
/// - `happy:///account?<key>`: happy-app's restore screen
///   (app/(app)/restore/index.tsx:141) and happy-agent (src/auth.ts:38).
/// - `happy://direct?<bundle>`: a computer's direct pairing code.
public enum HappyCode: Equatable, Sendable {
    /// A computer asking to be connected to a Happy account. A current
    /// CLI's code also carries a one-time pairing secret, which the reply
    /// must carry back (`LegacyPairingLink.terminalV3`); nil for an older
    /// CLI's code.
    case terminal(publicKey: Data, pairingSecret: Data? = nil)
    /// Another phone or browser asking for this phone's account.
    case account(publicKey: Data)
    /// A computer to pair with directly.
    case agentConnection(PairingLink)
    /// A Happy link whose content is broken, expired or from a newer app.
    case invalid(Problem)
    /// Not a Happy code at all.
    case notHappy

    public enum Problem: Equatable, Sendable {
        case terminal
        case account
        case agentConnection(PairingError)
    }

    public init(_ text: String, now: Date = Date()) {
        let text = text.trimmingCharacters(in: .whitespacesAndNewlines)
        if PairingLink.isAgentConnection(text) {
            do {
                self = .agentConnection(try PairingLink(text, now: now))
            } catch {
                self = .invalid(.agentConnection(error as? PairingError ?? .invalidCode))
            }
            return
        }
        if let link = LegacyPairingLink(text) {
            self = Self(link)
            return
        }
        // A broken v3 link is a broken terminal code, never an older one.
        if LegacyPairingLink.hasTerminalPrefix(text) {
            self = .invalid(.terminal)
        } else if text.hasPrefix(LegacyPairingLink.accountPrefix) {
            self = .invalid(.account)
        } else if let link = Self.webTerminalLink(text) {
            self = link.map(Self.init) ?? .invalid(.terminal)
        } else {
            self = .notHappy
        }
    }

    private init(_ link: LegacyPairingLink) {
        switch link {
        case .terminal(let key): self = .terminal(publicKey: key)
        case .terminalV3(let key, let secret): self = .terminal(publicKey: key, pairingSecret: secret)
        case .account(let key): self = .account(publicKey: key)
        }
    }

    /// The terminal link in happy-cli's web sign-in link; `.some(nil)` when
    /// the link is one but its fragment is broken, nil when it isn't one.
    private static func webTerminalLink(_ text: String) -> LegacyPairingLink?? {
        guard let url = URLComponents(string: text), url.scheme == "https" || url.scheme == "http",
              url.path.hasSuffix("/terminal/connect"), let fragment = url.fragment, !fragment.isEmpty
        else { return nil }
        return .some(LegacyPairingLink.webTerminal(fragment: fragment))
    }
}
