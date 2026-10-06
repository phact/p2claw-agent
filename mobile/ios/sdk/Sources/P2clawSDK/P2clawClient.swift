import Foundation
import LiveKitWebRTC
import UniFFI

/// Public entry point for the p2claw mobile SDK.
///
/// One client is meant to live for the lifetime of the app. Each call
/// to `connect` returns a fresh `Connection` against one box; the
/// underlying `LKRTCPeerConnectionFactory` and `URLSession` are shared
/// across all connections.
///
/// Connections are foreground-only on iOS. Backgrounding suspends
/// the network stack and the WebRTC peer drops; call sites must call
/// `connect` again after foregrounding rather than expecting the
/// existing `Connection` to silently reanimate.
public final class P2clawClient: @unchecked Sendable {
    /// Coord HTTPS base URL. Typically `https://coord.<parent>`. No
    /// trailing slash.
    public let coordUrl: String
    /// Extra STUN servers appended to coord's ICE-server list. Common
    /// values: `["stun:stun.l.google.com:19302"]` for fallback when
    /// coord doesn't provision STUN.
    public let stunServers: [String]
    /// Extra TURN servers — appended to coord's ICE-server list.
    public let turnServers: [TurnServer]
    /// Auth headers attached to `POST /v1/connect`. Typical values
    /// are the device-binding cert bearer + a per-request signature.
    public let authHeaders: [String: String]

    private let factory: LKRTCPeerConnectionFactory
    private let signalingBackend: URLSessionSignalingBackend

    public init(
        coordUrl: String,
        stunServers: [String] = [],
        turnServers: [TurnServer] = [],
        authHeaders: [String: String] = [:]
    ) {
        self.coordUrl = coordUrl
        self.stunServers = stunServers
        self.turnServers = turnServers
        self.authHeaders = authHeaders

        // LKRTCInitializeSSL must run once per process; WebRTC asserts
        // on duplicate calls. The framework's
        // `LKRTCPeerConnectionFactory.initialize()` is idempotent on
        // newer builds — the assert was removed in LiveKit's fork —
        // but we still gate to be safe.
        Self.initializeWebRTC()
        let encoderFactory = LKRTCDefaultVideoEncoderFactory()
        let decoderFactory = LKRTCDefaultVideoDecoderFactory()
        self.factory = LKRTCPeerConnectionFactory(
            encoderFactory: encoderFactory,
            decoderFactory: decoderFactory
        )
        self.signalingBackend = URLSessionSignalingBackend()
    }

    /// Establish a connection to the box identified by `boxUrl`.
    ///
    /// The URL is parsed for `alias` (+ optional `app`); the coord URL
    /// passed to the client is used verbatim for the signaling POST.
    /// Throws on any of: URL parse failure, coord rejection, WS
    /// auth-ack timeout, WebRTC handshake failure, or data-channel
    /// open failure.
    public func connect(boxUrl: String) async throws -> Connection {
        let address = try AddressGrammar.parse(boxUrl)
        let httpShim = signalingBackend.makeSignalingTransport()
        let wsShim = signalingBackend.makeWsTransport()
        let signaling = SignalingClient(http: httpShim, ws: wsShim)
        let session: SignalingSession
        do {
            session = try await signaling.connect(
                config: SignalingConfig(
                    coordUrl: coordUrl,
                    alias: address.alias,
                    app: address.app,
                    authHeaders: authHeaders.map { StringPair(name: $0.key, value: $0.value) }
                )
            )
        } catch let err as SignalingError {
            throw P2clawError.from(err)
        }

        let iceServers = IceServers.build(
            extraStun: stunServers,
            coordIceServers: session.iceServers(),
            extraTurn: turnServers
        )
        let (pc, dc) = try await WebRTCHandshake.establish(
            factory: factory,
            iceServers: iceServers,
            session: session
        )
        return Connection(pc: pc, dc: dc)
    }

    // ---------- WebRTC one-shot init ----------

    private static let initOnce: Void = {
        LKRTCInitializeSSL()
    }()

    private static func initializeWebRTC() {
        _ = initOnce
    }
}
