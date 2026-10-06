package com.p2claw.demo

import android.content.Intent
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.runtime.snapshots.SnapshotStateList
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import com.p2claw.sdk.P2clawClient
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import uniffi.p2claw_mobile.WsEvent

// Placeholder defaults: point them at a box of yours that exposes an
// echo app as `wstest`. Either value can be edited in the on-screen
// TextFields before tapping "Connect"; the demo passes them straight
// through to `P2clawClient.connect` + `Connection.openWebSocket`.
private const val COORD_URL = "https://coord.p2claw.com"
private const val DEFAULT_BOX_ALIAS = "quiet-river-3847"
private const val DEFAULT_APP = "wstest"
private const val DEFAULT_WS_PATH = "/"

// Total frames the round-trip exercises (5 text + 1 binary). Kept in
// one place so the logged "N/M" counters and the smoke harness's
// "all 6 frames" grep stay in sync.
private const val TOTAL_FRAMES = 6
private const val TAG = "p2claw-demo"

// Intent-extra contract for the smoke harness
// (`scripts/mobile-smoke-android.sh`): launching the demo with both
// `--es boxAlias <alias>` and `--es app <app>` populates the
// TextField defaults AND auto-triggers `runEchoRoundTrip` once
// Compose has settled. Missing either extra falls back to manual
// entry + manual tap of the Connect button — the existing
// developer-facing UX. Don't drift these names without updating the
// smoke script's `am start --es …` invocation too.
private const val EXTRA_BOX_ALIAS = "boxAlias"
private const val EXTRA_APP = "app"
private const val EXTRA_WS_PATH = "wsPath"

/**
 * Single-screen demo: pick a box alias + app, hit Connect, watch
 * frames echo back over a peer-to-peer WS through the box's
 * `WsForwarder`. Wire-level details (signaling, ICE, DC) are
 * abstracted by [P2clawClient]; the demo exercises only the public
 * SDK surface.
 */
class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val launchIntent: Intent? = intent
        setContent {
            MaterialTheme {
                Surface(modifier = Modifier.fillMaxSize()) {
                    DemoScreen(launchIntent)
                }
            }
        }
    }
}

@Composable
private fun DemoScreen(launchIntent: Intent?) {
    val context = LocalContext.current.applicationContext
    val client = remember { P2clawClient.create(context, COORD_URL) }
    val log = remember { mutableStateListOf<String>() }
    val intentAlias = launchIntent?.getStringExtra(EXTRA_BOX_ALIAS)
    val intentApp = launchIntent?.getStringExtra(EXTRA_APP)
    val intentPath = launchIntent?.getStringExtra(EXTRA_WS_PATH)
    var boxAlias by remember { mutableStateOf(intentAlias ?: DEFAULT_BOX_ALIAS) }
    var app by remember { mutableStateOf(intentApp ?: DEFAULT_APP) }
    var wsPath by remember { mutableStateOf(intentPath ?: DEFAULT_WS_PATH) }
    val scope = rememberCoroutineScope()
    val listState = rememberLazyListState()
    // Auto-trigger when both `boxAlias` + `app` extras are present.
    // Keyed on the intent identity so a repeated launch (force-stop +
    // restart) re-fires; manual launches don't trigger at all.
    LaunchedEffect(launchIntent) {
        if (intentAlias != null && intentApp != null) {
            android.util.Log.i(TAG, "intent autorun: boxAlias=$intentAlias app=$intentApp wsPath=${intentPath ?: DEFAULT_WS_PATH}")
            runEchoRoundTrip(client, boxAlias, app, wsPath, log)
        }
    }
    LaunchedEffect(log.size) {
        if (log.isNotEmpty()) listState.animateScrollToItem(log.lastIndex)
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Text("p2claw demo", style = MaterialTheme.typography.titleLarge)
        OutlinedTextField(
            value = boxAlias,
            onValueChange = { boxAlias = it },
            label = { Text("Machine alias") },
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
        )
        OutlinedTextField(
            value = app,
            onValueChange = { app = it },
            label = { Text("App") },
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
        )
        OutlinedTextField(
            value = wsPath,
            onValueChange = { wsPath = it },
            label = { Text("WS path") },
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
        )
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(onClick = {
                scope.launch { runEchoRoundTrip(client, boxAlias, app, wsPath, log) }
            }) { Text("Connect") }
            Button(onClick = { log.clear() }) { Text("Clear log") }
        }
        Spacer(modifier = Modifier.height(8.dp))
        LazyColumn(state = listState, modifier = Modifier.fillMaxSize()) {
            items(log) { line ->
                Text(line, style = MaterialTheme.typography.bodySmall)
            }
        }
    }
}

/**
 * Drive the WS round-trip and emit the success / failure markers
 * the smoke harness greps for. Contract:
 *
 * - `ws open` — fires once the WS handshake completes (i.e.
 *   [com.p2claw.sdk.Connection.openWebSocket] returns).
 * - `echo rx N/M` — per echoed frame; N is 1-indexed, M is
 *   [TOTAL_FRAMES] (= 5 text + 1 binary).
 * - `round-trip ok` — emitted after all M frames echo successfully;
 *   the harness also accepts the literal "all M frames" form as a
 *   fallback grep target.
 * - `connect failed: <reason>` / `round-trip failed: <reason>` —
 *   emitted on any error before round-trip completion.
 */
private suspend fun runEchoRoundTrip(
    client: P2clawClient,
    boxAlias: String,
    app: String,
    wsPath: String,
    log: SnapshotStateList<String>,
) {
    fun add(line: String) {
        log.add(line)
        android.util.Log.i(TAG, line)
    }
    withContext(Dispatchers.IO) {
        add("connecting to $app-$boxAlias …")
        val conn = runCatching {
            client.connect(
                P2clawClient.ConnectRequest(alias = boxAlias, app = app),
            )
        }.onFailure {
            add("connect failed: ${it.message}")
            return@withContext
        }.getOrThrow()

        add("DC open; opening WS $wsPath")
        val ws = runCatching { conn.openWebSocket(wsPath) }
            .onFailure {
                add("round-trip failed: ws open: ${it.message}")
                conn.close()
                return@withContext
            }.getOrThrow()
        add("ws open")
        var rx = 0
        try {
            for (i in 0 until 5) {
                val payload = "hello-$i"
                ws.sendText(payload)
                val echo = ws.next()
                if (echo == null) {
                    add("round-trip failed: ws closed before echo $i")
                    return@withContext
                }
                if (echo !is WsEvent.Message) {
                    add("round-trip failed: non-message event ${echo::class.simpleName} at frame $i")
                    return@withContext
                }
                val received = String(echo.data, Charsets.UTF_8)
                if (received != payload) {
                    add("round-trip failed: text mismatch at frame $i (sent=$payload, got=$received)")
                    return@withContext
                }
                rx++
                add("echo rx $rx/$TOTAL_FRAMES (text)")
            }
            // 256-byte 0..255 pattern, byte-identical echo expected.
            val bin = ByteArray(256) { (it and 0xFF).toByte() }
            ws.sendBinary(bin)
            val echo = ws.next()
            when {
                echo == null -> {
                    add("round-trip failed: ws closed before binary echo")
                    return@withContext
                }
                echo !is WsEvent.Message -> {
                    add("round-trip failed: non-message event ${echo::class.simpleName} on binary frame")
                    return@withContext
                }
                !echo.binary -> {
                    add("round-trip failed: binary frame returned with text opcode")
                    return@withContext
                }
                !echo.data.contentEquals(bin) -> {
                    add("round-trip failed: binary mismatch (sent ${bin.size}B, got ${echo.data.size}B)")
                    return@withContext
                }
            }
            rx++
            add("echo rx $rx/$TOTAL_FRAMES (binary)")
            add("round-trip ok — all $TOTAL_FRAMES frames")
        } finally {
            ws.close()
            conn.close()
        }
    }
}
