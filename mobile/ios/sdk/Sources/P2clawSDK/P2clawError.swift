import Foundation
import UniFFI

/// Errors raised by the SDK's public API.
///
/// Wire-codec errors and signaling errors from the Rust core flatten
/// into `.signaling` / `.wire` here so callers don't depend on the
/// UniFFI error shape directly.
public enum P2clawError: Error, Sendable {
    /// Box URL didn't parse into `[app.]alias.<parent>` form.
    case invalidBoxUrl(String)
    /// Signaling exchange against coord failed.
    case signaling(String)
    /// Wire codec error on the data channel.
    case wire(String)
    /// WebRTC peer connection failed during handshake or runtime.
    case webrtc(String)
    /// Box returned an HTTP-level error for a fetch.
    case http(status: UInt16, message: String)
    /// Box ended the WebSocket abnormally.
    case wsClosed(code: UInt16, reason: String)
    /// Connection torn down before the operation could complete.
    case connectionClosed
}

extension P2clawError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .invalidBoxUrl(let s): return "invalid app URL: \(s)"
        case .signaling(let s): return "signaling: \(s)"
        case .wire(let s): return "wire: \(s)"
        case .webrtc(let s): return "webrtc: \(s)"
        case .http(let status, let msg): return "http \(status): \(msg)"
        case .wsClosed(let code, let reason): return "ws closed \(code): \(reason)"
        case .connectionClosed: return "connection closed"
        }
    }
}

extension P2clawError {
    /// Lift a UniFFI `SignalingError` into the public shape.
    static func from(_ err: SignalingError) -> P2clawError {
        .signaling(err.localizedDescription)
    }

    /// Lift a UniFFI `CodecError` into the public shape.
    static func from(_ err: CodecError) -> P2clawError {
        .wire(err.localizedDescription)
    }
}
