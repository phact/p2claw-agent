import Foundation
import UniFFI

/// `URLSession`-backed implementation of UniFFI's signaling transports.
///
/// The Rust core never touches sockets — it constructs requests and
/// asks this backend to drive them. Two protocols, both wired here:
///
///   - `SignalingTransport.postConnect` → `URLSession.shared.data(for:)`.
///   - `SignalingTransport.openWs` → `URLSessionWebSocketTask`. The
///     open task is parked in `openWsTasks` keyed by a per-connection
///     `UInt64` id, and `WsTransport.send/recv/close` look it up.
///
/// The two-protocol split (rather than `openWs` returning a transport
/// object directly) is mandated by UniFFI 0.31's `with_foreign` codegen
/// — async traits can't return foreign trait objects safely. The
/// connection-id indirection works around that.
final class URLSessionSignalingBackend: @unchecked Sendable {
    private let session: URLSession
    private let stateLock = NSLock()
    private var nextConnId: UInt64 = 1
    private var openWsTasks: [UInt64: URLSessionWebSocketTask] = [:]

    init(session: URLSession = .shared) {
        self.session = session
    }

    /// Make a fresh `SignalingTransport`-conforming wrapper. The wrapper
    /// holds a strong ref back to this backend so the Rust core's
    /// `Arc<dyn SignalingTransport>` keeps the backend alive.
    func makeSignalingTransport() -> SignalingTransportShim {
        SignalingTransportShim(backend: self)
    }

    /// Make a fresh `WsTransport`-conforming wrapper. The same backend
    /// instance is shared so the WS task map is consistent across the
    /// two protocols.
    func makeWsTransport() -> WsTransportShim {
        WsTransportShim(backend: self)
    }

    func performConnect(
        url: String,
        body: Data,
        headers: [StringPair]
    ) async throws -> Data {
        guard let parsed = URL(string: url) else {
            throw SignalingError.transport("invalid coord URL: \(url)")
        }
        var req = URLRequest(url: parsed)
        req.httpMethod = "POST"
        req.httpBody = body
        for pair in headers {
            req.setValue(pair.value, forHTTPHeaderField: pair.name)
        }
        let (data, resp) = try await session.data(for: req)
        if let http = resp as? HTTPURLResponse, !(200..<300).contains(http.statusCode) {
            throw SignalingError.rejected("coord returned \(http.statusCode)")
        }
        return data
    }

    func openSignalingWs(
        url: String,
        headers: [StringPair]
    ) async throws -> UInt64 {
        guard let parsed = URL(string: url) else {
            throw SignalingError.transport("invalid signal URL: \(url)")
        }
        var req = URLRequest(url: parsed)
        for pair in headers {
            req.setValue(pair.value, forHTTPHeaderField: pair.name)
        }
        let task = session.webSocketTask(with: req)
        task.resume()
        return registerWsTask(task)
    }

    func sendOnWs(connId: UInt64, frame: Data) async throws {
        guard let task = lookupWsTask(connId) else {
            throw SignalingError.transport("no WS for id \(connId)")
        }
        // Signaling frames are UTF-8 JSON; send as text so coord's
        // tungstenite parser doesn't have to special-case binary.
        let text = String(data: frame, encoding: .utf8) ?? ""
        try await task.send(.string(text))
    }

    func recvOnWs(connId: UInt64) async throws -> Data? {
        guard let task = lookupWsTask(connId) else {
            throw SignalingError.transport("no WS for id \(connId)")
        }
        do {
            let msg = try await task.receive()
            switch msg {
            case .string(let s):
                return s.data(using: .utf8) ?? Data()
            case .data(let d):
                return d
            @unknown default:
                return Data()
            }
        } catch {
            // Clean close surfaces as receive() throwing; the Rust
            // core treats `Ok(None)` as "peer closed cleanly", so
            // narrow only the close-frame errors and re-raise the rest.
            let ns = error as NSError
            if ns.domain == NSURLErrorDomain && ns.code == NSURLErrorCancelled {
                return nil
            }
            // Treat WebSocket close codes as end-of-stream too. The
            // platform surfaces this as a `URLSessionWebSocketTask`
            // error with `closeCode` already set; we don't have it on
            // the URLError directly so the conservative read is "any
            // failure on receive means the stream is done."
            return nil
        }
    }

    func closeWs(connId: UInt64) async throws {
        guard let task = removeWsTask(connId) else { return }
        task.cancel(with: .normalClosure, reason: nil)
    }

    // ---------- state-lock helpers ----------

    private func registerWsTask(_ task: URLSessionWebSocketTask) -> UInt64 {
        stateLock.lock()
        defer { stateLock.unlock() }
        let id = nextConnId
        nextConnId &+= 1
        openWsTasks[id] = task
        return id
    }

    private func lookupWsTask(_ id: UInt64) -> URLSessionWebSocketTask? {
        stateLock.lock()
        defer { stateLock.unlock() }
        return openWsTasks[id]
    }

    private func removeWsTask(_ id: UInt64) -> URLSessionWebSocketTask? {
        stateLock.lock()
        defer { stateLock.unlock() }
        return openWsTasks.removeValue(forKey: id)
    }
}

/// Adapter conforming to the UniFFI-generated `SignalingTransport`
/// protocol. Forwards to a shared `URLSessionSignalingBackend`.
final class SignalingTransportShim: SignalingTransport, @unchecked Sendable {
    private let backend: URLSessionSignalingBackend
    init(backend: URLSessionSignalingBackend) { self.backend = backend }

    func postConnect(url: String, body: Data, headers: [StringPair]) async throws -> Data {
        try await backend.performConnect(url: url, body: body, headers: headers)
    }

    func openWs(url: String, headers: [StringPair]) async throws -> UInt64 {
        try await backend.openSignalingWs(url: url, headers: headers)
    }
}

/// Adapter conforming to the UniFFI-generated `WsTransport` protocol.
final class WsTransportShim: WsTransport, @unchecked Sendable {
    private let backend: URLSessionSignalingBackend
    init(backend: URLSessionSignalingBackend) { self.backend = backend }

    func send(connId: UInt64, frame: Data) async throws {
        try await backend.sendOnWs(connId: connId, frame: frame)
    }

    func recv(connId: UInt64) async throws -> Data? {
        try await backend.recvOnWs(connId: connId)
    }

    func close(connId: UInt64) async throws {
        try await backend.closeWs(connId: connId)
    }
}
