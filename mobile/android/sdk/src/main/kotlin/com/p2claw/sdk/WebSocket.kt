package com.p2claw.sdk

import kotlinx.coroutines.channels.Channel
import uniffi.p2claw_mobile.Frame
import uniffi.p2claw_mobile.Header
import uniffi.p2claw_mobile.ReadyState
import uniffi.p2claw_mobile.WsEvent
import uniffi.p2claw_mobile.WsShim

/**
 * Public WebSocket handle returned by [Connection.openWebSocket].
 *
 * Send via [sendText] / [sendBinary]; receive on the suspending
 * [next] entry point. [close] sends the RFC-6455 close frame; the
 * channel resolves to `null` once the box acks.
 */
class WebSocket internal constructor(
    private val conn: Connection,
    internal val shim: WsShim,
    internal val inbox: Channel<WsEvent>,
) : AutoCloseable {

    val streamId: UInt get() = shim.streamId()
    val readyState: ReadyState get() = shim.readyState()

    fun sendText(payload: String) {
        require(readyState == ReadyState.OPEN) { "WebSocket not open" }
        shim.sendText(payload.toByteArray(Charsets.UTF_8))
        drain()
    }

    fun sendBinary(payload: ByteArray) {
        require(readyState == ReadyState.OPEN) { "WebSocket not open" }
        shim.sendBinary(payload)
        drain()
    }

    /** Await the next [WsEvent]. Returns null after CLOSE / ERROR. */
    suspend fun next(): WsEvent? = inbox.receiveCatching().getOrNull()

    override fun close() {
        // 1000 = normal closure (RFC 6455 §7.4.1). The shim emits
        // a WsClose frame and moves to Closing; the inbox closes
        // when the box's matching close arrives.
        shim.close(NORMAL_CLOSURE, ByteArray(0))
        drain()
    }

    /**
     * Push every frame queued by the shim onto the data channel and
     * fan any newly-emitted events to the inbox. Called after each
     * app action and on each inbound frame delivery.
     */
    internal fun drain() {
        shim.takeOutgoing().forEach(conn::sendFrame)
        val events = shim.takeEvents()
        events.forEach { inbox.trySend(it) }
        // Close inbox once the state machine has reached Closed —
        // no further events will arrive.
        if (shim.readyState() == ReadyState.CLOSED) {
            inbox.close()
        }
    }

    companion object {
        // 1000 = normal closure (RFC 6455 §7.4.1). UShort literal
        // requires the explicit conversion; the underlying
        // WsShim.close call takes UShort.
        private val NORMAL_CLOSURE: UShort = 1000.toUShort()

        internal suspend fun open(
            conn: Connection,
            streamId: UInt,
            url: String,
            headers: List<Pair<String, String>>,
        ): WebSocket {
            val path = url.toByteArray(Charsets.UTF_8)
            val wireHeaders = headers.map { (n, v) ->
                Header(n.toByteArray(Charsets.UTF_8), v.toByteArray(Charsets.UTF_8))
            }
            val shim = WsShim.open(streamId, path, wireHeaders)
            val inbox = Channel<WsEvent>(Channel.UNLIMITED)
            val ws = WebSocket(conn, shim, inbox)
            conn.wsStreams[streamId] = WsAdapter(ws)
            // Push the initial WS_UPGRADE frame onto the wire.
            ws.drain()
            // Await Open / first terminal event. Messages before
            // Open buffer in the inbox for post-open consumption.
            while (true) {
                when (val event = ws.next()) {
                    null -> throw IllegalStateException("ws closed before open")
                    is WsEvent.Open -> return ws
                    is WsEvent.Close -> throw IllegalStateException(
                        "ws rejected: code=${event.code} reason=${String(event.reason, Charsets.UTF_8)}",
                    )
                    is WsEvent.Error -> throw IllegalStateException(event.message)
                    is WsEvent.Message -> inbox.trySend(event)
                }
            }
        }
    }
}

/**
 * Frame-delivery shim used by [Connection.dispatchFrame] for one
 * WebSocket stream. `handle_frame` on the underlying `WsShim` is
 * sans-I/O — feeds its state machine, then the WebSocket drains
 * the resulting outbox + events.
 */
internal class WsAdapter(private val ws: WebSocket) : PendingWebSocket {
    override fun deliver(frame: Frame) {
        ws.shim.handleFrame(frame)
        ws.drain()
    }
}
