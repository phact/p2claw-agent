package com.p2claw.sdk

import android.content.Context
import okhttp3.OkHttpClient
import org.webrtc.PeerConnection
import org.webrtc.PeerConnectionFactory
import uniffi.p2claw_mobile.SignalingClient
import uniffi.p2claw_mobile.SignalingConfig
import uniffi.p2claw_mobile.StringPair
import java.util.concurrent.TimeUnit

/**
 * Entry point to the p2claw mobile SDK.
 *
 * Construction is expensive (it spins up LiveKit's libwebrtc
 * `PeerConnectionFactory` + an OkHttpClient connection pool). Hold
 * a single instance per application and reuse for every
 * [connect] call.
 *
 * Threading: callers drive the SDK from any coroutine context; the
 * libwebrtc internals run their own threads. Suspending entry
 * points (`connect`, `Connection.openWebSocket`, etc.) bridge those
 * worlds via `kotlinx.coroutines`.
 */
class P2clawClient private constructor(
    private val appContext: Context,
    private val coordUrl: String,
    private val parentDomain: String,
    private val factory: PeerConnectionFactory,
    internal val http: OkHttpClient,
) {

    /**
     * Spec for [P2clawClient.connect] — the destination peer alias
     * plus optional app sub-domain (`<app>-<alias>` for
     * routed-to-app, bare alias for the box's home page).
     *
     * Auth headers (device-binding cert + signature for OAuth-gated
     * apps) are attached at the `connect` call so per-request headers
     * can rotate without rebuilding the client.
     */
    data class ConnectRequest(
        val alias: String,
        val app: String? = null,
        val authHeaders: List<Pair<String, String>> = emptyList(),
    )

    /**
     * Open a peer connection to [request].alias, run the full
     * signaling handshake, and return a live [Connection].
     *
     * Lifecycle: the returned connection owns a `PeerConnection` +
     * `DataChannel`. Caller MUST `close()` the connection to release
     * the underlying ICE + DTLS state — failing to do so leaks
     * native threads.
     */
    suspend fun connect(request: ConnectRequest): Connection {
        val transport = OkHttpSignalingTransport(http)
        val signaling = SignalingClient(
            http = transport,
            ws = transport,
        )
        val cfg = SignalingConfig(
            coordUrl = coordUrl,
            alias = request.alias,
            app = request.app,
            authHeaders = request.authHeaders.map { (n, v) -> StringPair(n, v) },
        )
        val session = signaling.connect(cfg)
        // Host the box's WsForwarder expects for app/alias routing —
        // mirrors how a browser would Host the request when fetching
        // `https://<app>-<alias>.<parentDomain>/…`. With no app, fall
        // back to the bare-alias homepage host.
        val host = if (request.app != null) {
            "${request.app}-${request.alias}.$parentDomain"
        } else {
            "${request.alias}.$parentDomain"
        }
        return Connection.open(this, factory, session, host)
    }

    /**
     * Tear down the libwebrtc factory + OkHttp pool. Subsequent
     * [connect] calls fail. Call from `Application.onTerminate` or
     * the equivalent process-end hook.
     */
    fun close() {
        factory.dispose()
        http.dispatcher.executorService.shutdown()
        http.connectionPool.evictAll()
    }

    companion object {
        /**
         * Construct a client.
         *
         * @param appContext application context (needed for
         *   libwebrtc's `PeerConnectionFactory.InitializationOptions`).
         * @param coordUrl coord origin (e.g. `https://coord.p2claw.com`).
         */
        fun create(
            appContext: Context,
            coordUrl: String,
            parentDomain: String = "p2claw.com",
        ): P2clawClient {
            PeerConnectionFactory.initialize(
                PeerConnectionFactory.InitializationOptions.builder(appContext)
                    .setEnableInternalTracer(false)
                    .createInitializationOptions(),
            )
            val factory = PeerConnectionFactory.builder().createPeerConnectionFactory()
            val http = OkHttpClient.Builder()
                .connectTimeout(10, TimeUnit.SECONDS)
                .readTimeout(0, TimeUnit.SECONDS) // signaling WS may sit idle for minutes
                .pingInterval(25, TimeUnit.SECONDS)
                .build()
            return P2clawClient(appContext, coordUrl, parentDomain, factory, http)
        }
    }
}
