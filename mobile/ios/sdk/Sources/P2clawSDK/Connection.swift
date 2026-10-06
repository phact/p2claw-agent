import Foundation
import LiveKitWebRTC
import UniFFI

/// One open peer-to-peer connection to a box. Holds the
/// `LKRTCPeerConnection`, the data channel, the wire decoder, and a
/// table of active `WsShim` / `FetchShim` state machines from the
/// UniFFI bindings. Each `openWebSocket` / `fetch` call allocates a
/// fresh stream id and registers its shim in the table; inbound DC
/// bytes are decoded into wire frames, routed to the right shim by
/// stream id, and any resulting outbound frames / app events are
/// drained back to the data channel / public handles.
///
/// All mutable state lives in the actor's isolation domain. The LKRTC
/// delegate callbacks are forwarded via `Task { await ... }` hops in
/// `DataChannelBridge`.
public actor Connection {
    private let pc: LKRTCPeerConnection
    private let dc: LKRTCDataChannel
    private let dcBridge: DataChannelBridge
    private let pcBridge: PeerConnectionBridge
    private let decoder: Decoder

    /// Odd-numbered ids for caller-initiated streams (mirrors the
    /// bootstrap convention; even ids are reserved for box-initiated
    /// streams should the wire ever grow them).
    private var nextStreamId: UInt32 = 1

    private var wsShims: [UInt32: WsShim] = [:]
    private var fetchShims: [UInt32: FetchShim] = [:]

    private var wsContinuations: [UInt32: AsyncStream<WebSocketMessage>.Continuation] = [:]
    private var wsOpenWaiters: [UInt32: CheckedContinuation<[Header], Error>] = [:]
    private var fetchWaiters: [UInt32: FetchWaiter] = [:]

    private var dataChannelReady = false
    private var dataChannelReadyWaiters: [CheckedContinuation<Void, Error>] = []

    private var isClosed = false

    init(pc: LKRTCPeerConnection, dc: LKRTCDataChannel) {
        self.pc = pc
        self.dc = dc
        self.dcBridge = DataChannelBridge()
        self.pcBridge = PeerConnectionBridge()
        self.decoder = Decoder()
        dcBridge.connection = self
        pcBridge.connection = self
        dc.delegate = dcBridge
        pc.delegate = pcBridge
        if dc.readyState == .open {
            dataChannelReady = true
        }
    }

    /// Open a multiplexed WebSocket stream to `url` (path + query on
    /// the box's HTTP routing surface). `headers` is folded into the
    /// `Sec-WebSocket-Protocol` / custom-header set sent on the
    /// upgrade. Resolves when the box returns `WsAccept`; the returned
    /// handle is immediately usable for send / receive.
    public func openWebSocket(
        url: String,
        headers: [String: String] = [:]
    ) async throws -> WebSocket {
        try checkOpen()
        try await waitForDataChannel()

        let streamId = allocateStreamId()
        let (path, wireHeaders) = wireHeaders(url: url, headers: headers, isWs: true)
        let shim = WsShim.open(streamId: streamId, path: path, headers: wireHeaders)
        wsShims[streamId] = shim
        pumpWsOutgoing(shim)

        // Block until the box answers WsAccept. The dispatch loop
        // resolves this continuation once the shim emits `Open`.
        let acceptHeaders: [Header] = try await withCheckedThrowingContinuation { cont in
            wsOpenWaiters[streamId] = cont
        }
        let subprotocol = headerValue("sec-websocket-protocol", from: acceptHeaders) ?? ""

        var continuationRef: AsyncStream<WebSocketMessage>.Continuation?
        let stream = AsyncStream<WebSocketMessage> { cont in continuationRef = cont }
        wsContinuations[streamId] = continuationRef

        // Capture only Sendable values for the callbacks — `self` is
        // an actor so it's already isolated, and shim ops are
        // thread-safe on the Rust side.
        let weakSelf = self
        let ws = WebSocket(
            streamId: streamId,
            subprotocol: subprotocol,
            incoming: stream,
            onSendText: { text in
                await weakSelf.wsSendText(streamId: streamId, payload: text)
            },
            onSendBinary: { data in
                await weakSelf.wsSendBinary(streamId: streamId, payload: data)
            },
            onClose: { code, reason in
                await weakSelf.wsClose(streamId: streamId, code: code, reason: reason)
            }
        )
        return ws
    }

    /// Issue an HTTP-shape request against the box and await the
    /// complete response. Body chunks are buffered into one `Data`;
    /// there is no streaming variant.
    public func fetch(
        method: String,
        url: String,
        headers: [String: String] = [:],
        body: Data = Data()
    ) async throws -> Response {
        try checkOpen()
        try await waitForDataChannel()

        let streamId = allocateStreamId()
        let (path, wireHeaders) = wireHeaders(url: url, headers: headers, isWs: false)
        let methodBytes = Data(method.utf8)
        let shim = FetchShim.request(
            streamId: streamId,
            method: methodBytes,
            path: path,
            headers: wireHeaders,
            body: body
        )
        fetchShims[streamId] = shim
        pumpFetchOutgoing(shim)

        return try await withCheckedThrowingContinuation { cont in
            fetchWaiters[streamId] = FetchWaiter(continuation: cont)
        }
    }

    /// Tear down the data channel + peer connection. Idempotent.
    public func close() async {
        guard !isClosed else { return }
        isClosed = true
        for (_, cont) in wsContinuations { cont.finish() }
        wsContinuations.removeAll()
        for (_, waiter) in wsOpenWaiters {
            waiter.resume(throwing: P2clawError.connectionClosed)
        }
        wsOpenWaiters.removeAll()
        for (_, fetch) in fetchWaiters {
            fetch.continuation.resume(throwing: P2clawError.connectionClosed)
        }
        fetchWaiters.removeAll()
        for waiter in dataChannelReadyWaiters {
            waiter.resume(throwing: P2clawError.connectionClosed)
        }
        dataChannelReadyWaiters.removeAll()
        dc.close()
        pc.close()
    }

    // ---------- delegate hops ----------

    /// Called by `DataChannelBridge` when WebRTC delivers an inbound
    /// message. Feeds bytes into the wire decoder, then routes the
    /// resulting frames into the matching shim.
    func dispatchInbound(_ data: Data) async {
        guard !isClosed else { return }
        decoder.push(bytes: data)
        while true {
            let frame: Frame?
            do {
                frame = try decoder.nextFrame()
            } catch let err as CodecError {
                for (_, waiter) in fetchWaiters {
                    waiter.continuation.resume(throwing: P2clawError.from(err))
                }
                await close()
                return
            } catch {
                await close()
                return
            }
            guard let next = frame else { return }
            await routeFrame(next)
        }
    }

    /// Called by `DataChannelBridge` whenever the data-channel state
    /// changes. The transition from connecting → open releases any
    /// callers parked in `waitForDataChannel`.
    func dataChannelStateChanged(_ state: LKRTCDataChannelState) async {
        guard state == .open, !dataChannelReady else { return }
        dataChannelReady = true
        let waiters = dataChannelReadyWaiters
        dataChannelReadyWaiters.removeAll()
        for waiter in waiters { waiter.resume(returning: ()) }
    }

    /// Called by `PeerConnectionBridge` on `failed` / `closed`.
    func peerConnectionDropped() async {
        await close()
    }

    // ---------- internals ----------

    private func routeFrame(_ frame: Frame) async {
        let kind = frameKindOf(frame: frame)
        let streamId = streamIdOf(frame)
        switch kind {
        case .ping:
            // Mirror back a pong with the same nonce so the box keeps
            // the channel warm.
            if case .ping(let nonce) = frame {
                let pong = Frame.pong(nonce: nonce)
                sendFrame(pong)
            }
            return
        case .probe:
            if case .probe(let id, _) = frame {
                sendFrame(.probeAck(id: id))
            }
            return
        case .goaway:
            await close()
            return
        default:
            break
        }
        guard let streamId else { return }
        if let shim = wsShims[streamId] {
            _ = shim.handleFrame(frame: frame)
            pumpWsOutgoing(shim)
            drainWsEvents(streamId: streamId, shim: shim)
            return
        }
        if let shim = fetchShims[streamId] {
            _ = shim.handleFrame(frame: frame)
            pumpFetchOutgoing(shim)
            drainFetchEvents(streamId: streamId, shim: shim)
            return
        }
        // Stream not registered — silently drop. Common during
        // teardown when the box's last frame races our close.
    }

    private func drainWsEvents(streamId: UInt32, shim: WsShim) {
        for event in shim.takeEvents() {
            switch event {
            case .open(let headers):
                if let cont = wsOpenWaiters.removeValue(forKey: streamId) {
                    cont.resume(returning: headers)
                }
            case .message(let binary, let data):
                guard let cont = wsContinuations[streamId] else { continue }
                if binary {
                    cont.yield(.binary(data))
                } else {
                    let text = String(data: data, encoding: .utf8) ?? ""
                    cont.yield(.text(text))
                }
            case .close(_, _):
                wsContinuations[streamId]?.finish()
                wsContinuations.removeValue(forKey: streamId)
                wsShims.removeValue(forKey: streamId)
                if let pending = wsOpenWaiters.removeValue(forKey: streamId) {
                    // Close before open → surface as a handshake error.
                    pending.resume(throwing: P2clawError.connectionClosed)
                }
            case .error(let message):
                if let pending = wsOpenWaiters.removeValue(forKey: streamId) {
                    pending.resume(throwing: P2clawError.wire(message))
                }
                wsContinuations[streamId]?.finish()
                wsContinuations.removeValue(forKey: streamId)
                wsShims.removeValue(forKey: streamId)
            }
        }
    }

    private func drainFetchEvents(streamId: UInt32, shim: FetchShim) {
        guard var waiter = fetchWaiters[streamId] else { return }
        for event in shim.takeEvents() {
            switch event {
            case .head(let status, let headers):
                waiter.status = status
                waiter.headers = headers.map { (decodeAscii($0.name), decodeAscii($0.value)) }
            case .chunk(let data):
                waiter.body.append(data)
            case .trailers(_):
                // The public Response shape carries no trailers.
                break
            case .end:
                let response = Response(
                    status: waiter.status,
                    headers: waiter.headers,
                    body: waiter.body
                )
                waiter.continuation.resume(returning: response)
                fetchWaiters.removeValue(forKey: streamId)
                fetchShims.removeValue(forKey: streamId)
                return
            case .error(let code, let message):
                let msg = String(data: message, encoding: .utf8) ?? ""
                waiter.continuation.resume(throwing: P2clawError.http(status: code, message: msg))
                fetchWaiters.removeValue(forKey: streamId)
                fetchShims.removeValue(forKey: streamId)
                return
            }
        }
        fetchWaiters[streamId] = waiter
    }

    private func pumpWsOutgoing(_ shim: WsShim) {
        for frame in shim.takeOutgoing() { sendFrame(frame) }
    }

    private func pumpFetchOutgoing(_ shim: FetchShim) {
        for frame in shim.takeOutgoing() { sendFrame(frame) }
    }

    /// Largest single data-channel message we send. SCTP rejects messages
    /// over the negotiated max (64 KiB when the box advertises none), so a
    /// larger frame goes out as consecutive messages; the box decodes
    /// frames from the concatenated byte stream.
    static let maxMessageBytes = 16 * 1024

    private func sendFrame(_ frame: Frame) {
        let bytes = encodeFrame(frame: frame)
        for start in stride(from: 0, to: bytes.count, by: Self.maxMessageBytes) {
            let end = min(start + Self.maxMessageBytes, bytes.count)
            let chunk = bytes.subdata(in: bytes.startIndex + start ..< bytes.startIndex + end)
            dc.sendData(LKRTCDataBuffer(data: chunk, isBinary: true))
        }
    }

    private func allocateStreamId() -> UInt32 {
        let id = nextStreamId
        nextStreamId &+= 2
        return id
    }

    private func waitForDataChannel() async throws {
        if dataChannelReady { return }
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
            dataChannelReadyWaiters.append(cont)
        }
    }

    private func checkOpen() throws {
        if isClosed { throw P2clawError.connectionClosed }
    }

    // ---------- WS send / close hops from public handle ----------

    func wsSendText(streamId: UInt32, payload: String) async {
        guard let shim = wsShims[streamId] else { return }
        shim.sendText(payload: Data(payload.utf8))
        pumpWsOutgoing(shim)
    }

    func wsSendBinary(streamId: UInt32, payload: Data) async {
        guard let shim = wsShims[streamId] else { return }
        shim.sendBinary(payload: payload)
        pumpWsOutgoing(shim)
    }

    func wsClose(streamId: UInt32, code: UInt16, reason: String) async {
        guard let shim = wsShims[streamId] else { return }
        shim.close(code: code, reason: Data(reason.utf8))
        pumpWsOutgoing(shim)
        drainWsEvents(streamId: streamId, shim: shim)
    }

    // ---------- header / URL helpers ----------

    /// Build the wire-frame `path` bytes + `Header[]` for an outbound
    /// fetch or WS upgrade. The `url` is parsed for its path + query;
    /// scheme + host are dropped (the box already knows it's itself).
    /// `isWs` is reserved for any future WS-specific header handling
    /// (e.g. injecting `Sec-WebSocket-Protocol` from a separate field).
    private func wireHeaders(
        url: String,
        headers: [String: String],
        isWs: Bool
    ) -> (Data, [Header]) {
        // Take everything from the first `/` of the URL, or fall back
        // to `/` if the input is a bare host or path-only string.
        let path: String
        if let parsed = URL(string: url) {
            let base = parsed.path.isEmpty ? "/" : parsed.path
            if let query = parsed.query, !query.isEmpty {
                path = "\(base)?\(query)"
            } else {
                path = base
            }
        } else {
            path = url.first == "/" ? url : "/" + url
        }
        let pathBytes = Data(path.utf8)

        // Wire headers: lowercased name + raw value. The box's
        // forwarder is case-insensitive on receive but we normalize
        // outbound for cache-key stability and to match the bootstrap.
        var wire: [Header] = []
        for (k, v) in headers {
            wire.append(Header(name: Data(k.lowercased().utf8), value: Data(v.utf8)))
        }
        return (pathBytes, wire)
    }

    private func streamIdOf(_ frame: Frame) -> UInt32? {
        switch frame {
        case .req(let s, _, _, _, _),
             .res(let s, _, _, _),
             .data(let s, _, _),
             .end(let s),
             .err(let s, _, _),
             .trailers(let s, _),
             .wsUpgrade(let s, _, _),
             .wsAccept(let s, _),
             .wsMsg(let s, _, _),
             .wsClose(let s, _, _):
            return s
        case .ping, .pong, .probe, .probeAck, .goaway:
            return nil
        }
    }

    private func headerValue(_ name: String, from headers: [Header]) -> String? {
        let needle = name.lowercased()
        for h in headers {
            let key = decodeAscii(h.name).lowercased()
            if key == needle { return decodeAscii(h.value) }
        }
        return nil
    }

    private func decodeAscii(_ data: Data) -> String {
        String(data: data, encoding: .utf8) ?? ""
    }
}

/// In-flight `fetch` accumulator. The dispatch loop assembles
/// status + headers + body chunks here and resumes the continuation
/// when the shim emits `End`.
private struct FetchWaiter {
    let continuation: CheckedContinuation<Response, Error>
    var status: UInt16 = 0
    var headers: [(String, String)] = []
    var body: Data = Data()
}
