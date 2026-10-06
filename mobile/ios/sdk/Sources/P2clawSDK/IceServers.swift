import Foundation
import LiveKitWebRTC

/// One TURN server entry. STUN-only entries use `TurnServer(urls:)` with
/// empty credentials.
public struct TurnServer: Sendable, Hashable {
    public let urls: [String]
    public let username: String?
    public let credential: String?

    public init(urls: [String], username: String? = nil, credential: String? = nil) {
        self.urls = urls
        self.username = username
        self.credential = credential
    }
}

enum IceServers {
    /// Translate the SDK config + coord's ICE-server list into
    /// `LKRTCIceServer` instances for the peer connection. STUN entries
    /// from `extraStun` land first, then coord's TURN entries (which
    /// carry credentials), then any caller-provided TURN entries.
    ///
    /// `coordIceServers` arrives as opaque JSON strings — coord emits
    /// each entry as the raw `LKRTCIceServer` shape so the platform
    /// layer can hand them off verbatim. Parse defensively: skip
    /// entries that don't decode rather than failing the whole
    /// connection.
    static func build(
        extraStun: [String],
        coordIceServers: [String],
        extraTurn: [TurnServer]
    ) -> [LKRTCIceServer] {
        var out: [LKRTCIceServer] = []
        if !extraStun.isEmpty {
            out.append(LKRTCIceServer(urlStrings: extraStun))
        }
        for raw in coordIceServers {
            if let server = parseIceServer(raw) {
                out.append(server)
            }
        }
        for t in extraTurn {
            out.append(
                LKRTCIceServer(
                    urlStrings: t.urls,
                    username: t.username,
                    credential: t.credential
                )
            )
        }
        return out
    }

    /// Decode one ICE-server JSON entry. Accepted shapes mirror what
    /// coord emits today:
    ///   {"urls":["stun:..."]}
    ///   {"urls":["turn:..."],"username":"u","credential":"c"}
    /// `urls` may also be a single string for backward compatibility
    /// with older coord builds.
    private static func parseIceServer(_ raw: String) -> LKRTCIceServer? {
        guard let data = raw.data(using: .utf8),
              let json = try? JSONSerialization.jsonObject(with: data),
              let obj = json as? [String: Any]
        else { return nil }

        let urls: [String]
        if let arr = obj["urls"] as? [String] {
            urls = arr
        } else if let single = obj["urls"] as? String {
            urls = [single]
        } else if let arr = obj["url"] as? [String] {
            urls = arr
        } else if let single = obj["url"] as? String {
            urls = [single]
        } else {
            return nil
        }
        let username = obj["username"] as? String
        let credential = obj["credential"] as? String
        return LKRTCIceServer(
            urlStrings: urls,
            username: username,
            credential: credential
        )
    }
}
