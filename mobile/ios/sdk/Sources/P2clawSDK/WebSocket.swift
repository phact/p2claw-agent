import Foundation

/// Message yielded by the `WebSocket.incoming` async sequence.
public enum WebSocketMessage: Sendable, Equatable {
    case text(String)
    case binary(Data)
}

/// Handle returned by `Connection.openWebSocket`. Backed by a wire
/// stream on the shared data channel; closes cleanly when the holder
/// goes out of scope or calls `close()`.
public final class WebSocket: Sendable {
    /// Stream identifier on the multiplexed data channel.
    public let streamId: UInt32
    /// Subprotocol the box negotiated, or empty if none.
    public let subprotocol: String

    /// Async sequence of inbound text / binary messages. The sequence
    /// ends (without throwing) when the peer closes cleanly.
    public let incoming: AsyncStream<WebSocketMessage>

    private let onSendText: @Sendable (String) async throws -> Void
    private let onSendBinary: @Sendable (Data) async throws -> Void
    private let onClose: @Sendable (UInt16, String) async -> Void

    init(
        streamId: UInt32,
        subprotocol: String,
        incoming: AsyncStream<WebSocketMessage>,
        onSendText: @escaping @Sendable (String) async throws -> Void,
        onSendBinary: @escaping @Sendable (Data) async throws -> Void,
        onClose: @escaping @Sendable (UInt16, String) async -> Void
    ) {
        self.streamId = streamId
        self.subprotocol = subprotocol
        self.incoming = incoming
        self.onSendText = onSendText
        self.onSendBinary = onSendBinary
        self.onClose = onClose
    }

    /// Send one message — text or binary.
    public func send(_ message: WebSocketMessage) async throws {
        switch message {
        case .text(let s): try await onSendText(s)
        case .binary(let d): try await onSendBinary(d)
        }
    }

    /// Initiate a clean close. Idempotent. `code` follows RFC 6455
    /// (1000 = normal, 1001 = going away, etc.).
    public func close(code: UInt16 = 1000, reason: String = "") async {
        await onClose(code, reason)
    }
}
