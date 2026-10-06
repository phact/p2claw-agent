import Foundation
import LiveKitWebRTC

/// `LKRTCDataChannelDelegate` that forwards messages + state changes
/// into an actor-isolated `Connection`. The delegate runs on
/// WebRTC's worker thread; we hop into the actor via `Task` for every
/// callback so all state mutation stays in one isolation domain.
///
/// `Connection` is held weakly to avoid retain cycles — the delegate
/// outlives the connection only briefly during teardown, and a
/// dropped weak ref is the signal to stop forwarding.
final class DataChannelBridge: NSObject, LKRTCDataChannelDelegate, @unchecked Sendable {
    weak var connection: Connection?

    func dataChannel(
        _ dataChannel: LKRTCDataChannel,
        didReceiveMessageWith buffer: LKRTCDataBuffer
    ) {
        let data = buffer.data
        let connection = self.connection
        Task { await connection?.dispatchInbound(data) }
    }

    func dataChannelDidChangeState(_ dataChannel: LKRTCDataChannel) {
        let state = dataChannel.readyState
        let connection = self.connection
        Task { await connection?.dataChannelStateChanged(state) }
    }
}

/// `LKRTCPeerConnectionDelegate` for connection-level state. Most
/// callbacks are no-ops here — the SDK exposes only the up/down
/// signal that surfaces as `Connection.close()` when the peer drops.
final class PeerConnectionBridge: NSObject, LKRTCPeerConnectionDelegate, @unchecked Sendable {
    weak var connection: Connection?
    /// Per-handshake ICE candidate sink. Set during `WebRTCHandshake`,
    /// cleared once the connection finishes establishing.
    var iceCandidateSink: ((LKRTCIceCandidate) -> Void)?
    /// Continuation that resolves once `connected` is reached, or
    /// rejects on `failed` / `closed`. Cleared after one fire.
    var connectedContinuation: CheckedContinuation<Void, Error>?
    /// Continuation that resolves with the data channel the box
    /// opens on its side. The SDK is the answerer; we don't create
    /// the DC locally — it arrives via `didOpen`.
    var dataChannelContinuation: CheckedContinuation<LKRTCDataChannel, Error>?

    func peerConnection(_ pc: LKRTCPeerConnection, didChange newState: LKRTCPeerConnectionState) {
        switch newState {
        case .connected:
            connectedContinuation?.resume(returning: ())
            connectedContinuation = nil
        case .failed, .closed:
            let err = P2clawError.webrtc("peer connection \(newState)")
            connectedContinuation?.resume(throwing: err)
            connectedContinuation = nil
            dataChannelContinuation?.resume(throwing: err)
            dataChannelContinuation = nil
            let connection = self.connection
            Task { await connection?.peerConnectionDropped() }
        default:
            break
        }
    }

    func peerConnection(_ pc: LKRTCPeerConnection, didGenerate candidate: LKRTCIceCandidate) {
        iceCandidateSink?(candidate)
    }

    // Unused — required by the protocol.
    func peerConnection(_ pc: LKRTCPeerConnection, didChange newState: LKRTCSignalingState) {}
    func peerConnection(_ pc: LKRTCPeerConnection, didAdd stream: LKRTCMediaStream) {}
    func peerConnection(_ pc: LKRTCPeerConnection, didRemove stream: LKRTCMediaStream) {}
    func peerConnectionShouldNegotiate(_ pc: LKRTCPeerConnection) {}
    func peerConnection(_ pc: LKRTCPeerConnection, didChange newState: LKRTCIceConnectionState) {}
    func peerConnection(_ pc: LKRTCPeerConnection, didChange newState: LKRTCIceGatheringState) {}
    func peerConnection(_ pc: LKRTCPeerConnection, didRemove candidates: [LKRTCIceCandidate]) {}
    func peerConnection(_ pc: LKRTCPeerConnection, didOpen dataChannel: LKRTCDataChannel) {
        dataChannelContinuation?.resume(returning: dataChannel)
        dataChannelContinuation = nil
    }
}
