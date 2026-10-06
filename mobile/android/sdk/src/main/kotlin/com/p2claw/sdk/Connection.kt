package com.p2claw.sdk

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject
import org.webrtc.DataChannel
import org.webrtc.IceCandidate
import org.webrtc.MediaConstraints
import org.webrtc.PeerConnection
import org.webrtc.PeerConnectionFactory
import org.webrtc.RtpReceiver
import org.webrtc.SdpObserver
import org.webrtc.SessionDescription
import uniffi.p2claw_mobile.Decoder
import uniffi.p2claw_mobile.SignalingEvent
import uniffi.p2claw_mobile.SignalingSession
import uniffi.p2claw_mobile.encodeFrame
import java.nio.ByteBuffer
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger

/** Largest single data-channel message the SDK sends. */
private const val MAX_MESSAGE_BYTES = 16 * 1024

/**
 * One peer-to-peer connection to a p2claw box.
 *
 * Wraps a single LiveKit `PeerConnection` + its primary
 * `DataChannel`. Inbound DC binary frames feed the Rust wire
 * `Decoder`; the resulting `Frame`s drive per-stream state machines
 * (`WsShim`, `FetchShim`) which the public-facing [WebSocket] /
 * [Response] handles wrap.
 *
 * Lifecycle: created by [P2clawClient.connect]. Caller MUST
 * [close] to release the underlying ICE + DTLS state. Dropping the
 * reference without close leaks libwebrtc threads.
 */
class Connection internal constructor(
    internal val peer: PeerConnection,
    internal val dc: DataChannel,
    private val scope: CoroutineScope,
    private val session: SignalingSession,
    /**
     * Host header value the box's `WsForwarder` parses to resolve
     * the app + alias on every WS upgrade — derived from
     * `<app>-<alias>.<parentDomain>` at connect time. Auto-injected
     * by [openWebSocket] if the caller didn't already supply one.
     */
    private val host: String,
) : AutoCloseable {

    // Per-stream maps. Stream ids are minted by us (odd) for streams
    // we open and by the box (even) for box-initiated streams — the
    // even/odd split is the bootstrap convention and avoids id
    // collisions without per-stream signaling.
    private val nextStreamId = AtomicInteger(1)
    internal val wsStreams = ConcurrentHashMap<UInt, PendingWebSocket>()

    private val decoder = Decoder()

    /**
     * Open a WebSocket through the box to [url], with the given
     * upgrade [headers] attached. The shim drives the same
     * client-state machine bootstrap uses, so the box-side
     * `WsForwarder` sees an identical wire trace.
     */
    suspend fun openWebSocket(
        url: String,
        headers: List<Pair<String, String>> = emptyList(),
    ): WebSocket {
        // Auto-inject Host unless the caller pinned a different value.
        // WsForwarder rejects the upgrade with 400 ("missing Host
        // header") if it isn't present — bootstrap relies on the
        // browser to add Host, but native libwebrtc clients have to
        // do it explicitly.
        val withHost = if (headers.any { it.first.equals("Host", ignoreCase = true) }) {
            headers
        } else {
            listOf("Host" to host) + headers
        }
        return WebSocket.open(this, mintStreamId(), url, withHost)
    }

    // Only the WebSocket surface is exposed; wrapping `FetchShim` needs
    // an adapter that surfaces suspending body iteration.

    override fun close() {
        scope.cancel()
        dc.close()
        peer.close()
        // Best-effort: tell coord we're done so it can release any
        // outstanding signaling state. Errors are swallowed — at this
        // point the connection is going away regardless.
        scope.launch { runCatching { session.close() } }
    }

    /**
     * Stream ids: we use odd ids (1, 3, 5, ...) for client-initiated
     * streams. Box-initiated streams (currently none in this SDK's
     * client surface — they'd need handler registration) would use
     * even ids.
     */
    private fun mintStreamId(): UInt {
        var id: Int
        do {
            id = nextStreamId.getAndAdd(2)
        } while (id <= 0)
        return id.toUInt()
    }

    private val sendLock = Any()

    internal fun sendFrame(frame: uniffi.p2claw_mobile.Frame) {
        val bytes = encodeFrame(frame)
        // SCTP rejects messages over the negotiated max (64 KiB when the
        // box advertises none), so a larger frame goes out as consecutive
        // messages. The lock keeps one frame's pieces contiguous when
        // several threads send at once.
        synchronized(sendLock) {
            var off = 0
            while (off < bytes.size) {
                val len = minOf(MAX_MESSAGE_BYTES, bytes.size - off)
                // DataChannel.Buffer copies the payload internally.
                dc.send(DataChannel.Buffer(ByteBuffer.wrap(bytes, off, len), true))
                off += len
            }
        }
    }

    internal fun onDataChannelMessage(buffer: DataChannel.Buffer) {
        if (!buffer.binary) return
        val bytes = ByteArray(buffer.data.remaining())
        buffer.data.get(bytes)
        decoder.push(bytes)
        while (true) {
            val frame = decoder.nextFrame() ?: return
            dispatchFrame(frame)
        }
    }

    private fun dispatchFrame(frame: uniffi.p2claw_mobile.Frame) {
        // Per-frame routing: pull the stream id off, look up the
        // matching pending WS / fetch handle, hand the frame off.
        // Frames without a stream id (Ping, Pong, Probe, ProbeAck,
        // Goaway) are control frames; the SDK doesn't surface them
        // to callers.
        when (frame) {
            is uniffi.p2claw_mobile.Frame.Res,
            is uniffi.p2claw_mobile.Frame.Data,
            is uniffi.p2claw_mobile.Frame.End,
            is uniffi.p2claw_mobile.Frame.Err,
            is uniffi.p2claw_mobile.Frame.Trailers,
            is uniffi.p2claw_mobile.Frame.WsAccept,
            is uniffi.p2claw_mobile.Frame.WsMsg,
            is uniffi.p2claw_mobile.Frame.WsClose -> {
                val sid = streamIdOf(frame)
                val ws = wsStreams[sid]
                ws?.deliver(frame)
            }
            else -> { /* control frame, ignored in this client surface */ }
        }
    }

    companion object {
        private const val TAG = "p2claw-sdk"

        /**
         * Open the WebRTC peer connection against the box, drive the
         * SDP offer / answer + ICE candidate exchange through
         * [session], wait for the data channel to open, and return.
         */
        internal suspend fun open(
            client: P2clawClient,
            factory: PeerConnectionFactory,
            session: SignalingSession,
            host: String,
        ): Connection {
            val rtcConfig = PeerConnection.RTCConfiguration(
                session.iceServers().mapNotNull(::parseIceServer),
            ).apply {
                sdpSemantics = PeerConnection.SdpSemantics.UNIFIED_PLAN
            }
            val dcOpened = CompletableDeferred<DataChannel>()
            val dispatchScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

            // PeerConnection observer threading: libwebrtc fires
            // callbacks on its own signaling/network threads. We
            // unblock those quickly by routing work onto
            // `dispatchScope`.
            val observer = object : PeerConnection.Observer {
                override fun onSignalingChange(state: PeerConnection.SignalingState) {
                    android.util.Log.i(TAG, "signaling state -> $state")
                }
                override fun onIceConnectionChange(state: PeerConnection.IceConnectionState) {
                    android.util.Log.i(TAG, "ice connection state -> $state")
                }
                override fun onIceConnectionReceivingChange(receiving: Boolean) {}
                override fun onIceGatheringChange(state: PeerConnection.IceGatheringState) {
                    android.util.Log.i(TAG, "ice gathering state -> $state")
                }
                override fun onIceCandidate(candidate: IceCandidate) {
                    android.util.Log.i(TAG, "ice candidate ${candidate.sdpMid} ${candidate.sdp.take(80)}")
                    dispatchScope.launch {
                        val payload = JSONObject().apply {
                            put("kind", "candidate")
                            put("candidate", JSONObject().apply {
                                put("candidate", candidate.sdp)
                                put("sdpMid", candidate.sdpMid ?: "")
                                put("sdpMLineIndex", candidate.sdpMLineIndex)
                            })
                        }
                        runCatching {
                            session.sendPayload(payload.toString().toByteArray())
                        }
                    }
                }
                override fun onIceCandidatesRemoved(candidates: Array<out IceCandidate>) {}
                override fun onAddStream(stream: org.webrtc.MediaStream) {}
                override fun onRemoveStream(stream: org.webrtc.MediaStream) {}
                override fun onDataChannel(channel: DataChannel) {
                    // Box-initiated DC (the offer path uses the
                    // client-created DC, so this fires for re-offer
                    // edge cases only).
                    dcOpened.complete(channel)
                }
                override fun onRenegotiationNeeded() {}
                override fun onAddTrack(receiver: RtpReceiver, streams: Array<out org.webrtc.MediaStream>) {}
            }

            // Box-as-offerer flow (matches bootstrap's wire shape):
            //
            //   box → {"kind":"offer", "sdp":"..."}
            //   us  → setRemoteDescription(offer) → createAnswer → setLocalDescription
            //   us  → {"kind":"answer", "sdp":"..."}
            //   box ↔ us  exchange {"kind":"candidate", "candidate":{...}} both ways
            //   PeerConnection's onDataChannel fires when the offerer's
            //   DC mline is realised; we wait on `dcOpened` for that.
            android.util.Log.i(TAG, "ice servers=${session.iceServers().size}")

            val peer = factory.createPeerConnection(rtcConfig, observer)
                ?: error("PeerConnectionFactory.createPeerConnection returned null")

            // Box's signaling stream doesn't guarantee `offer → candidate*`
            // ordering — candidates can arrive before the offer.
            // `pc.addIceCandidate()` SILENTLY DROPS when the remote
            // description isn't set yet (no error, no callback). Buffer
            // any pre-offer candidates and replay them once the offer
            // has been applied. iOS SDK uses the same pattern.
            val sigState = SignalingState()

            // Drive the signaling loop: apply offer, answer, candidates.
            // `dcOpened` resolves when `onDataChannel` fires (box-side
            // DC is created with its own id/label by the offerer).
            dispatchScope.launch {
                var idx = 0
                while (true) {
                    val event = session.nextEvent() ?: run {
                        android.util.Log.w(TAG, "signaling.nextEvent returned null — session ended")
                        return@launch
                    }
                    idx++
                    when (event) {
                        is SignalingEvent.Payload -> {
                            val preview = String(event.bytes, Charsets.UTF_8).take(160)
                            android.util.Log.i(TAG, "signal[$idx] payload ${event.bytes.size}B: $preview")
                            runCatching { handleSignalPayload(peer, session, sigState, event.bytes) }
                                .onFailure { android.util.Log.w(TAG, "signal[$idx] handle threw: ${it.message}") }
                        }
                        is SignalingEvent.Error -> {
                            android.util.Log.w(TAG, "signal[$idx] error -> break")
                            break
                        }
                        is SignalingEvent.Ended -> {
                            android.util.Log.i(TAG, "signal[$idx] ended -> break")
                            break
                        }
                    }
                }
            }

            val dc = dcOpened.await()
            android.util.Log.i(TAG, "data channel opened-callback: label=${dc.label()} id=${dc.id()} state=${dc.state()}")
            val dcReady = CompletableDeferred<Unit>()
            dc.registerObserver(object : DataChannel.Observer {
                override fun onBufferedAmountChange(previousAmount: Long) {}
                override fun onStateChange() {
                    android.util.Log.i(TAG, "dc state -> ${dc.state()}")
                    if (dc.state() == DataChannel.State.OPEN) {
                        dcReady.complete(Unit)
                    }
                }
                override fun onMessage(buffer: DataChannel.Buffer) {
                    pendingInbound.add(DataChannel.Buffer(buffer.data, buffer.binary))
                }
            })
            if (dc.state() == DataChannel.State.OPEN) dcReady.complete(Unit)
            dcReady.await()
            android.util.Log.i(TAG, "DC ready")

            val conn = Connection(peer, dc, dispatchScope, session, host)
            dc.registerObserver(object : DataChannel.Observer {
                override fun onBufferedAmountChange(previousAmount: Long) {}
                override fun onStateChange() {}
                override fun onMessage(buffer: DataChannel.Buffer) {
                    conn.onDataChannelMessage(buffer)
                }
            })
            pendingInbound.forEach { conn.onDataChannelMessage(it) }
            pendingInbound.clear()
            return conn
        }

        private val pendingInbound = mutableListOf<DataChannel.Buffer>()

        // Box-as-offerer wire shape: `{"kind":"offer"|"candidate", ...}`.
        // We're the answerer — apply the offer, mint + send an answer,
        // buffer candidates that race ahead of the offer, ingest in
        // arrival order once the remote description is set.
        private suspend fun handleSignalPayload(
            peer: PeerConnection,
            session: SignalingSession,
            state: SignalingState,
            bytes: ByteArray,
        ) {
            val text = String(bytes)
            val json = JSONObject(text)
            when (val kind = json.optString("kind")) {
                "offer" -> {
                    val sdp = json.getString("sdp")
                    android.util.Log.i(TAG, "applying offer (${sdp.length}B)")
                    setRemote(peer, SessionDescription(SessionDescription.Type.OFFER, sdp))
                    val answer = createAnswer(peer)
                    setLocal(peer, answer)
                    android.util.Log.i(TAG, "sending answer (${answer.description.length}B)")
                    session.sendPayload(
                        JSONObject()
                            .put("kind", "answer")
                            .put("sdp", answer.description)
                            .toString()
                            .toByteArray(),
                    )
                    val drained = state.markRemoteSetAndDrain()
                    if (drained.isNotEmpty()) {
                        android.util.Log.i(TAG, "replaying ${drained.size} buffered ice candidates")
                        for (c in drained) peer.addIceCandidate(c)
                    }
                }
                "answer" -> {
                    // Defensive: in case the box rerole-flips, accept
                    // an answer too. Not expected on the current wire.
                    val sdp = json.getString("sdp")
                    android.util.Log.i(TAG, "applying answer (${sdp.length}B)")
                    setRemote(peer, SessionDescription(SessionDescription.Type.ANSWER, sdp))
                    val drained = state.markRemoteSetAndDrain()
                    if (drained.isNotEmpty()) {
                        android.util.Log.i(TAG, "replaying ${drained.size} buffered ice candidates")
                        for (c in drained) peer.addIceCandidate(c)
                    }
                }
                "candidate" -> {
                    val c = json.getJSONObject("candidate")
                    val candidate = IceCandidate(
                        c.optString("sdpMid", ""),
                        c.optInt("sdpMLineIndex", 0),
                        c.getString("candidate"),
                    )
                    if (state.bufferIfNoRemote(candidate)) {
                        android.util.Log.i(TAG, "buffering pre-offer ice ${candidate.sdp.take(80)}")
                    } else {
                        android.util.Log.i(TAG, "adding remote ice ${candidate.sdp.take(80)}")
                        peer.addIceCandidate(candidate)
                    }
                }
                else -> {
                    android.util.Log.w(TAG, "unknown signal kind='$kind' (${bytes.size}B)")
                }
            }
        }

        private suspend fun setRemote(peer: PeerConnection, sd: SessionDescription) {
            val deferred = CompletableDeferred<Unit>()
            peer.setRemoteDescription(object : SdpObserver {
                override fun onCreateSuccess(sd: SessionDescription) {}
                override fun onSetSuccess() { deferred.complete(Unit) }
                override fun onCreateFailure(error: String) {}
                override fun onSetFailure(error: String) {
                    android.util.Log.w(TAG, "setRemote failure: $error")
                    deferred.completeExceptionally(IllegalStateException(error))
                }
            }, sd)
            deferred.await()
        }

        private suspend fun setLocal(peer: PeerConnection, sd: SessionDescription) {
            val deferred = CompletableDeferred<Unit>()
            peer.setLocalDescription(object : SdpObserver {
                override fun onCreateSuccess(sd: SessionDescription) {}
                override fun onSetSuccess() { deferred.complete(Unit) }
                override fun onCreateFailure(error: String) {}
                override fun onSetFailure(error: String) {
                    android.util.Log.w(TAG, "setLocal failure: $error")
                    deferred.completeExceptionally(IllegalStateException(error))
                }
            }, sd)
            deferred.await()
        }

        private suspend fun createAnswer(peer: PeerConnection): SessionDescription =
            withContext(Dispatchers.Default) {
                val deferred = CompletableDeferred<SessionDescription>()
                peer.createAnswer(object : SdpObserver {
                    override fun onCreateSuccess(sd: SessionDescription) { deferred.complete(sd) }
                    override fun onSetSuccess() {}
                    override fun onCreateFailure(error: String) {
                        deferred.completeExceptionally(IllegalStateException(error))
                    }
                    override fun onSetFailure(error: String) {}
                }, MediaConstraints())
                deferred.await()
            }

        /**
         * Per-connection signaling-handshake state. Currently just the
         * remote-description-set flag + a pre-offer ICE candidate
         * buffer; `addIceCandidate` is a silent no-op on Android
         * WebRTC when no remote description is set yet, so any
         * candidate that races ahead of the offer would otherwise
         * vanish. Replayed on offer/answer apply.
         */
        internal class SignalingState {
            private val lock = Any()
            private var remoteSet = false
            private val buffered = ArrayList<IceCandidate>()

            /** @return `true` if buffered (no remote yet), `false` if caller should add immediately. */
            fun bufferIfNoRemote(candidate: IceCandidate): Boolean = synchronized(lock) {
                if (remoteSet) return false
                buffered += candidate
                true
            }

            /** Mark remote-description-set and return any buffered candidates to replay (FIFO). */
            fun markRemoteSetAndDrain(): List<IceCandidate> = synchronized(lock) {
                remoteSet = true
                val out = ArrayList(buffered)
                buffered.clear()
                out
            }
        }

        /**
         * Parse a single ICE-server JSON descriptor into LiveKit's
         * `IceServer`. Returns null on malformed entries —
         * silently dropping is safer than aborting the connect.
         */
        private fun parseIceServer(spec: String): PeerConnection.IceServer? {
            val json = runCatching { JSONObject(spec) }.getOrNull() ?: return null
            val urls = mutableListOf<String>()
            json.opt("urls")?.let {
                when (it) {
                    is String -> urls.add(it)
                    is org.json.JSONArray -> {
                        for (i in 0 until it.length()) urls.add(it.getString(i))
                    }
                }
            }
            if (urls.isEmpty()) return null
            val builder = PeerConnection.IceServer.builder(urls)
            json.optString("username").takeIf { it.isNotEmpty() }?.let(builder::setUsername)
            json.optString("credential").takeIf { it.isNotEmpty() }?.let(builder::setPassword)
            return builder.createIceServer()
        }
    }
}


internal fun streamIdOf(frame: uniffi.p2claw_mobile.Frame): UInt = when (frame) {
    is uniffi.p2claw_mobile.Frame.Req -> frame.streamId
    is uniffi.p2claw_mobile.Frame.Res -> frame.streamId
    is uniffi.p2claw_mobile.Frame.Data -> frame.streamId
    is uniffi.p2claw_mobile.Frame.End -> frame.streamId
    is uniffi.p2claw_mobile.Frame.Err -> frame.streamId
    is uniffi.p2claw_mobile.Frame.Trailers -> frame.streamId
    is uniffi.p2claw_mobile.Frame.WsUpgrade -> frame.streamId
    is uniffi.p2claw_mobile.Frame.WsAccept -> frame.streamId
    is uniffi.p2claw_mobile.Frame.WsMsg -> frame.streamId
    is uniffi.p2claw_mobile.Frame.WsClose -> frame.streamId
    is uniffi.p2claw_mobile.Frame.Ping,
    is uniffi.p2claw_mobile.Frame.Pong,
    is uniffi.p2claw_mobile.Frame.Probe,
    is uniffi.p2claw_mobile.Frame.ProbeAck,
    is uniffi.p2claw_mobile.Frame.Goaway -> 0u
}

internal interface PendingWebSocket {
    fun deliver(frame: uniffi.p2claw_mobile.Frame)
}
