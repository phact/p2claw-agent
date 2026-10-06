import Foundation
import LiveKitWebRTC
import UniFFI

/// Drives the WebRTC offer/answer/candidate exchange over the
/// signaling-relay payloads. **The box is the offerer**, this SDK is
/// the answerer — same as the browser bootstrap. Box also creates the
/// data channel, so we wait for it to arrive via
/// `peerConnection(_:didOpen:)` rather than constructing it locally.
///
/// Wire envelope shape on the relay (matches the bootstrap):
///
/// ```
/// {"kind":"offer",     "sdp":"..."}                                   (box → us)
/// {"kind":"candidate", "candidate":{"candidate":"...", "sdpMid":"", "sdpMLineIndex":0}}
/// {"kind":"answer",    "sdp":"..."}                                   (us → box)
/// ```
///
/// Note: `sdpMid` may be the empty string (not absent). Decoded as
/// optional + treated identically whether `""` or `nil`.
enum WebRTCHandshake {
    /// Outer signaling envelope on the relay.
    private struct Envelope: Codable {
        let kind: String
        var sdp: String?
        var candidate: CandidatePayload?
    }

    /// Nested ICE-candidate payload inside the envelope.
    private struct CandidatePayload: Codable {
        let candidate: String
        let sdpMid: String?
        let sdpMLineIndex: Int32
    }

    /// Build the peer connection, wait for the box's offer, send an
    /// answer back, and return the connected `(pc, dc)` pair ready
    /// for `Connection`.
    static func establish(
        factory: LKRTCPeerConnectionFactory,
        iceServers: [LKRTCIceServer],
        session: SignalingSession
    ) async throws -> (LKRTCPeerConnection, LKRTCDataChannel) {
        let config = LKRTCConfiguration()
        config.iceServers = iceServers
        config.sdpSemantics = .unifiedPlan
        config.continualGatheringPolicy = .gatherContinually
        config.bundlePolicy = .maxBundle
        config.rtcpMuxPolicy = .require

        let constraints = LKRTCMediaConstraints(
            mandatoryConstraints: nil,
            optionalConstraints: nil
        )

        let bridge = PeerConnectionBridge()
        guard let pc = factory.peerConnection(with: config, constraints: constraints, delegate: bridge) else {
            throw P2clawError.webrtc("peerConnection() returned nil")
        }

        // Send local candidates through the signaling relay as they
        // gather (trickle ICE).
        bridge.iceCandidateSink = { candidate in
            let payload = CandidatePayload(
                candidate: candidate.sdp,
                sdpMid: candidate.sdpMid,
                sdpMLineIndex: candidate.sdpMLineIndex
            )
            let env = Envelope(kind: "candidate", sdp: nil, candidate: payload)
            if let bytes = encode(env) {
                Task { try? await session.sendPayload(bytes: bytes) }
            }
        }

        // The box creates the DC; we receive it via `didOpen`. The
        // pump runs as a child task and is cancelled once the DC is
        // open, so ICE candidates arriving after that are not relayed.
        // On pump errors the box would fail to answer and the PC's
        // `.failed` state rejects our continuations, so failure still
        // propagates.
        let pumpTask = Task<Void, Error> {
            try await pumpSignalingInbound(session: session, pc: pc)
        }
        do {
            async let dataChannel = waitForDataChannel(bridge: bridge)
            async let connected: Void = waitForConnected(bridge: bridge)
            let dc = try await dataChannel
            _ = try await connected
            pumpTask.cancel()
            bridge.iceCandidateSink = nil
            return (pc, dc)
        } catch {
            pumpTask.cancel()
            pc.close()
            throw error
        }
    }

    // ---------- internal helpers ----------

    private static func waitForConnected(bridge: PeerConnectionBridge) async throws {
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
            bridge.connectedContinuation = cont
        }
    }

    private static func waitForDataChannel(bridge: PeerConnectionBridge) async throws -> LKRTCDataChannel {
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<LKRTCDataChannel, Error>) in
            bridge.dataChannelContinuation = cont
        }
    }

    /// Consume signaling events for the lifetime of the handshake.
    /// Resolves when the session ends or the peer connection drops.
    /// Errors propagate out (caller treats as handshake failure).
    private static func pumpSignalingInbound(
        session: SignalingSession,
        pc: LKRTCPeerConnection
    ) async throws {
        var pendingCandidates: [LKRTCIceCandidate] = []
        var remoteSet = false
        while let event = await session.nextEvent() {
            switch event {
            case .payload(_, let bytes):
                guard let env = decode(bytes) else { continue }
                switch env.kind {
                case "offer":
                    guard let sdp = env.sdp else { continue }
                    let offer = LKRTCSessionDescription(type: .offer, sdp: sdp)
                    try await setRemote(pc: pc, sdp: offer)
                    remoteSet = true
                    // Flush queued candidates received before the
                    // remote description was set.
                    for c in pendingCandidates { pc.add(c) }
                    pendingCandidates.removeAll()
                    let answer = try await createAnswer(pc: pc)
                    try await setLocal(pc: pc, sdp: answer)
                    let env = Envelope(kind: "answer", sdp: answer.sdp, candidate: nil)
                    if let bytes = encode(env) {
                        try await session.sendPayload(bytes: bytes)
                    }
                case "candidate":
                    guard let payload = env.candidate else { continue }
                    // Empty-string `sdpMid` is treated the same as nil
                    // — `LKRTCIceCandidate` accepts an optional.
                    let mid = payload.sdpMid?.isEmpty == false ? payload.sdpMid : nil
                    let candidate = LKRTCIceCandidate(
                        sdp: payload.candidate,
                        sdpMLineIndex: payload.sdpMLineIndex,
                        sdpMid: mid
                    )
                    if remoteSet {
                        pc.add(candidate)
                    } else {
                        pendingCandidates.append(candidate)
                    }
                case "end":
                    pc.close()
                    return
                default:
                    break
                }
            case .error(let code, let message):
                throw P2clawError.signaling("\(code): \(message ?? "")")
            case .ended:
                return
            }
        }
    }

    private static func createAnswer(pc: LKRTCPeerConnection) async throws -> LKRTCSessionDescription {
        try await withCheckedThrowingContinuation { cont in
            let constraints = LKRTCMediaConstraints(
                mandatoryConstraints: nil,
                optionalConstraints: nil
            )
            pc.answer(for: constraints) { desc, err in
                if let err = err {
                    cont.resume(throwing: P2clawError.webrtc(err.localizedDescription))
                } else if let desc = desc {
                    cont.resume(returning: desc)
                } else {
                    cont.resume(throwing: P2clawError.webrtc("answer returned no SDP"))
                }
            }
        }
    }

    private static func setLocal(pc: LKRTCPeerConnection, sdp: LKRTCSessionDescription) async throws {
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
            pc.setLocalDescription(sdp) { err in
                if let err = err {
                    cont.resume(throwing: P2clawError.webrtc(err.localizedDescription))
                } else {
                    cont.resume(returning: ())
                }
            }
        }
    }

    private static func setRemote(pc: LKRTCPeerConnection, sdp: LKRTCSessionDescription) async throws {
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
            pc.setRemoteDescription(sdp) { err in
                if let err = err {
                    cont.resume(throwing: P2clawError.webrtc(err.localizedDescription))
                } else {
                    cont.resume(returning: ())
                }
            }
        }
    }

    private static func encode(_ env: Envelope) -> Data? {
        try? JSONEncoder().encode(env)
    }

    private static func decode(_ data: Data) -> Envelope? {
        try? JSONDecoder().decode(Envelope.self, from: data)
    }
}
