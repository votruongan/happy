import Foundation

/// What a scanned or pasted QR payload asks for. Mirrors the links happy-app
/// accepts in useConnectTerminal.ts (auth/terminalPairing.ts) and
/// useConnectAccount.ts.
///
/// The key is the requester's X25519 public key, base64url. The formats are
/// fixed by the CLI and the other apps, including the odd triple slash of
/// the account link.
public enum PairingLink: Equatable, Sendable {
    /// A terminal (CLI / desktop) asking to be connected to this account,
    /// from a CLI older than pairing v3: `happy://terminal?<pk>`.
    case terminal(publicKey: Data)
    /// A current CLI's terminal link, `happy://pair/terminal?key=<pk>&s=<ps>`.
    /// `ps` is a one-time pairing secret that is only in the QR code or URL;
    /// the reply carries it so the CLI can tell this app's reply from any
    /// other.
    case terminalV3(publicKey: Data, pairingSecret: Data)
    /// Another phone or browser asking for this account (device linking).
    case account(publicKey: Data)

    public static let terminalPrefix = "happy://terminal?"
    public static let terminalV3Prefix = "happy://pair/terminal?"
    public static let accountPrefix = "happy:///account?"

    public init?(_ string: String) {
        let trimmed = string.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.hasPrefix(Self.terminalV3Prefix) {
            let params = Self.queryParams(String(trimmed.dropFirst(Self.terminalV3Prefix.count)))
            // Without its secret a v3 link is invalid, never a legacy one.
            guard let key = params["key"].flatMap(Self.decodeKey),
                  let secret = params["s"].flatMap(Self.decodeKey)
            else { return nil }
            self = .terminalV3(publicKey: key, pairingSecret: secret)
        } else if trimmed.hasPrefix(Self.terminalPrefix) {
            guard let key = Self.decodeKey(String(trimmed.dropFirst(Self.terminalPrefix.count))) else { return nil }
            self = .terminal(publicKey: key)
        } else if trimmed.hasPrefix(Self.accountPrefix) {
            guard let key = Self.decodeKey(String(trimmed.dropFirst(Self.accountPrefix.count))) else { return nil }
            self = .account(publicKey: key)
        } else {
            return nil
        }
    }

    /// Has a terminal link's prefix, either form. A scanner keeps only
    /// these; `init` decides whether one is valid.
    public static func hasTerminalPrefix(_ string: String) -> Bool {
        let trimmed = string.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.hasPrefix(terminalV3Prefix) || trimmed.hasPrefix(terminalPrefix)
    }

    public var publicKey: Data {
        switch self {
        case .terminal(let key), .terminalV3(let key, _), .account(let key): return key
        }
    }

    /// A terminal link of either form.
    public var isTerminal: Bool {
        switch self {
        case .terminal, .terminalV3: return true
        case .account: return false
        }
    }

    public var urlString: String {
        switch self {
        case .terminal(let key): return Self.terminalPrefix + Self.encodeKey(key)
        case .terminalV3(let key, let secret): return "\(Self.terminalV3Prefix)key=\(Self.encodeKey(key))&s=\(Self.encodeKey(secret))"
        case .account(let key): return Self.accountPrefix + Self.encodeKey(key)
        }
    }

    /// Base64url without padding, decoded leniently. Kept local so HappyWire
    /// has no dependency on HappyCrypto.
    private static func decodeKey(_ string: String) -> Data? {
        var base64 = string.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        let remainder = base64.utf8.count % 4
        if remainder != 0 {
            base64 += String(repeating: "=", count: 4 - remainder)
        }
        guard let data = Data(base64Encoded: base64), data.count == 32 else { return nil }
        return data
    }

    private static func encodeKey(_ key: Data) -> String {
        key.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    /// URLSearchParams: each name's first value, percent-decoded.
    private static func queryParams(_ query: String) -> [String: String] {
        var params: [String: String] = [:]
        for pair in query.split(separator: "&", omittingEmptySubsequences: true) {
            let parts = pair.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
            let name = String(parts[0]).removingPercentEncoding ?? String(parts[0])
            let value = parts.count > 1 ? (String(parts[1]).removingPercentEncoding ?? String(parts[1])) : ""
            if params[name] == nil { params[name] = value }
        }
        return params
    }
}

extension PairingLink: CustomStringConvertible {
    /// The kind only: a v3 link carries its pairing secret, which must not
    /// reach logs.
    public var description: String {
        switch self {
        case .terminal: return "PairingLink.terminal"
        case .terminalV3: return "PairingLink.terminalV3"
        case .account: return "PairingLink.account"
        }
    }
}
