import Foundation

extension Strings {
    /// The question every terminal code asks before it is answered, and the
    /// warning for a request someone else answered (terminal/index.tsx,
    /// useConnectTerminal.ts).
    public enum Terminal {
        public static var connectTerminal: String { localized("terminal.connectTerminal", "Connect Terminal") }
        public static var terminalRequestDescription: String {
            localized("terminal.terminalRequestDescription", "A terminal is requesting to connect to your Happy Coder account. This will allow the terminal to send and receive messages securely.")
        }
        public static var acceptConnection: String { localized("terminal.acceptConnection", "Accept Connection") }
        public static var reject: String { localized("terminal.reject", "Reject") }
        public static var alreadyConnectedTitle: String { localized("terminal.alreadyConnectedTitle", "Terminal already connected") }
        public static var alreadyConnectedMessage: String {
            localized("terminal.alreadyConnectedMessage", "Someone else may have connected this terminal before you. Do not use it. On your computer, run `happy auth logout`, then `happy auth login` and scan the new code.")
        }
    }
}
