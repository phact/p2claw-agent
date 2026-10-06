package com.p2claw.sdk

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.channels.Channel
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import okio.ByteString
import okio.ByteString.Companion.toByteString
import uniffi.p2claw_mobile.SignalingException
import uniffi.p2claw_mobile.StringPair

/**
 * One signaling-WebSocket connection driven by OkHttp. Rust's
 * `WsTransport` traits in / out are split here:
 *
 * - `send` writes to the OkHttp socket directly.
 * - `recv` suspends on an inbound channel filled by
 *   `WebSocketListener.onMessage`.
 *
 * Text and binary frames both arrive as `ByteArray` to keep the
 * Rust-facing surface UTF-8-agnostic — coord today emits text, but
 * accepting both keeps the wire forward-compatible.
 */
internal class WsHandle(
    private val url: String,
    private val headers: List<StringPair>,
    private val http: OkHttpClient,
) {
    // Reader-side buffer. Unbounded keeps tight RTT loops from
    // dropping under bursty signaling traffic; in practice each
    // connection ships only a handful of frames before closing.
    private val inbox = Channel<ByteArray>(Channel.UNLIMITED)
    private val opened = CompletableDeferred<Unit>()

    @Volatile
    private var socket: WebSocket? = null

    @Volatile
    private var closed = false

    suspend fun connect() {
        val req = Request.Builder()
            .url(url)
            .apply { headers.forEach { addHeader(it.name, it.value) } }
            .build()
        http.newWebSocket(req, Listener())
        // OkHttp surfaces failures via `onFailure`. We don't await
        // `onOpen` here — `send` queues until the socket flushes,
        // matching OkHttp's documented buffering semantics.
        opened.await()
    }

    fun send(frame: ByteArray) {
        val sock = socket
            ?: throw SignalingException.Transport("ws not yet open")
        // Coord's signaling channel is text-only JSON. `send(String)`
        // sets the WS opcode to TEXT; the Rust core hands us valid
        // UTF-8.
        val sent = sock.send(String(frame, Charsets.UTF_8))
        if (!sent) {
            throw SignalingException.Transport("ws send rejected")
        }
    }

    suspend fun recv(): ByteArray? {
        if (closed) return null
        return inbox.receiveCatching().getOrNull()
    }

    fun close() {
        closed = true
        // 1000 = normal closure. OkHttp ignores second `close` calls,
        // making this idempotent against repeated platform invocations.
        socket?.close(1000, null)
        inbox.close()
    }

    private inner class Listener : WebSocketListener() {
        override fun onOpen(webSocket: WebSocket, response: Response) {
            socket = webSocket
            opened.complete(Unit)
        }

        override fun onMessage(webSocket: WebSocket, text: String) {
            inbox.trySend(text.toByteArray(Charsets.UTF_8))
        }

        override fun onMessage(webSocket: WebSocket, bytes: ByteString) {
            inbox.trySend(bytes.toByteArray())
        }

        override fun onClosing(webSocket: WebSocket, code: Int, reason: String) {
            // Mirror RFC 6455's "we'll send a close in response".
            webSocket.close(code, reason)
        }

        override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
            closed = true
            inbox.close()
        }

        override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
            closed = true
            if (!opened.isCompleted) {
                opened.completeExceptionally(
                    SignalingException.Transport(t.message ?: "ws failure"),
                )
            }
            inbox.close(t)
        }
    }
}

private fun ByteArray.toByteString(): ByteString = toByteString(0, size)
