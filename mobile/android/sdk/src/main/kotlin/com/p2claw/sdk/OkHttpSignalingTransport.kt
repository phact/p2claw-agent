package com.p2claw.sdk

import kotlinx.coroutines.suspendCancellableCoroutine
import okhttp3.Call
import okhttp3.Callback
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import uniffi.p2claw_mobile.SignalingException
import uniffi.p2claw_mobile.SignalingTransport
import uniffi.p2claw_mobile.StringPair
import uniffi.p2claw_mobile.WsTransport
import java.io.IOException
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

/**
 * Platform implementation of `SignalingTransport` + `WsTransport`
 * over a shared OkHttpClient. Both traits run on the same client so
 * the connection pool, DNS cache, and timeouts are uniform across
 * the connect POST and the signaling-stream WebSocket.
 *
 * `openWs` returns an opaque `u64` id; `WsTransport.send/recv/close`
 * look it up in `connections`. The UniFFI codegen for `with_foreign`
 * traits can't yield foreign trait objects through `async_trait`, so
 * this two-trait split is the documented workaround in
 * `crates/p2claw-mobile/src/signaling.rs`.
 */
internal class OkHttpSignalingTransport(
    private val http: OkHttpClient,
) : SignalingTransport, WsTransport {

    private val nextId = AtomicLong(1L)
    private val connections = ConcurrentHashMap<Long, WsHandle>()

    override suspend fun postConnect(
        url: String,
        body: ByteArray,
        headers: List<StringPair>,
    ): ByteArray {
        val req = Request.Builder()
            .url(url)
            .post(body.toRequestBody(JSON))
            .apply { headers.forEach { addHeader(it.name, it.value) } }
            .build()
        return suspendCancellableCoroutine { cont ->
            val call = http.newCall(req)
            cont.invokeOnCancellation { call.cancel() }
            call.enqueue(object : Callback {
                override fun onFailure(call: Call, e: IOException) {
                    cont.resumeWithException(SignalingException.Transport(e.message ?: "io"))
                }

                override fun onResponse(call: Call, response: Response) {
                    response.use {
                        if (!it.isSuccessful) {
                            cont.resumeWithException(
                                SignalingException.Transport("http ${it.code}"),
                            )
                            return
                        }
                        val bytes = it.body?.bytes() ?: ByteArray(0)
                        cont.resume(bytes)
                    }
                }
            })
        }
    }

    override suspend fun openWs(url: String, headers: List<StringPair>): ULong {
        val id = nextId.getAndIncrement()
        // Bounded buffers keep memory predictable when the Rust side
        // is slow to drain. Backpressure surfaces as a closed channel.
        val handle = WsHandle(url, headers, http)
        connections[id] = handle
        handle.connect()
        return id.toULong()
    }

    override suspend fun send(connId: ULong, frame: ByteArray) {
        val handle = connections[connId.toLong()]
            ?: throw SignalingException.Transport("unknown conn_id $connId")
        handle.send(frame)
    }

    override suspend fun recv(connId: ULong): ByteArray? {
        val handle = connections[connId.toLong()]
            ?: throw SignalingException.Transport("unknown conn_id $connId")
        return handle.recv()
    }

    override suspend fun close(connId: ULong) {
        val handle = connections.remove(connId.toLong()) ?: return
        handle.close()
    }

    private companion object {
        // Coord accepts only JSON on `/v1/connect`. The UTF-8 payload
        // from the Rust core is already encoded as a JSON object body.
        val JSON = "application/json; charset=utf-8".toMediaType()
    }
}
