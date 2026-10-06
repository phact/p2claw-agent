import SwiftUI
import P2clawSDK

/// Minimal single-screen demo. Three inputs (coord URL + box URL +
/// echo path), one button to connect + open WS, and a scrollable log
/// of round-tripped messages. No persistence — state lives only for
/// the lifetime of the foreground app.
struct ContentView: View {
    @State private var coordUrl: String = "https://coord.p2claw.com"
    @State private var boxUrl: String = "https://abc.p2claw.com"
    @State private var wsPath: String = "/echo"
    @State private var outgoing: String = "hello"
    @State private var log: [String] = []
    @State private var status: String = "idle"
    @State private var ws: WebSocket?
    @State private var client: P2clawClient?
    @State private var connection: Connection?

    var body: some View {
        VStack(spacing: 12) {
            Text("p2claw demo")
                .font(.title2)
                .frame(maxWidth: .infinity, alignment: .leading)

            inputField("Coord URL", text: $coordUrl)
            inputField("App URL", text: $boxUrl)
            inputField("WS path", text: $wsPath)

            HStack {
                Button("Connect + open WS") { Task { await connect() } }
                    .disabled(ws != nil)
                Button("Send") { Task { await send() } }
                    .disabled(ws == nil)
                Button("Close") { Task { await closeAll() } }
                    .disabled(connection == nil)
            }

            inputField("Outgoing payload", text: $outgoing)

            Text("status: \(status)")
                .font(.caption)
                .foregroundStyle(.secondary)
                .frame(maxWidth: .infinity, alignment: .leading)

            ScrollView {
                VStack(alignment: .leading, spacing: 4) {
                    ForEach(Array(log.enumerated()), id: \.offset) { _, line in
                        Text(line).font(.system(.caption, design: .monospaced))
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            }
        }
        .padding()
    }

    private func inputField(_ label: String, text: Binding<String>) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(label).font(.caption2).foregroundStyle(.secondary)
            TextField(label, text: text)
                .textFieldStyle(.roundedBorder)
                .autocorrectionDisabled()
                .textInputAutocapitalization(.never)
        }
    }

    // ---------- actions ----------

    private func connect() async {
        do {
            status = "connecting…"
            let c = P2clawClient(coordUrl: coordUrl)
            let conn = try await c.connect(boxUrl: boxUrl)
            let socket = try await conn.openWebSocket(url: wsPath)
            client = c
            connection = conn
            ws = socket
            status = "open (\(socket.subprotocol.isEmpty ? "no subproto" : socket.subprotocol))"
            log.append("[open] streamId=\(socket.streamId)")
            Task { await pump(socket) }
        } catch {
            status = "error: \(error.localizedDescription)"
            log.append("[error] \(error.localizedDescription)")
        }
    }

    private func send() async {
        guard let ws else { return }
        do {
            try await ws.send(.text(outgoing))
            log.append("→ \(outgoing)")
        } catch {
            log.append("[send error] \(error.localizedDescription)")
        }
    }

    private func closeAll() async {
        if let ws { await ws.close() }
        if let connection { await connection.close() }
        ws = nil
        connection = nil
        client = nil
        status = "closed"
    }

    private func pump(_ socket: WebSocket) async {
        for await msg in socket.incoming {
            switch msg {
            case .text(let s): log.append("← \(s)")
            case .binary(let d): log.append("← <\(d.count) bytes>")
            }
        }
        log.append("[ws closed]")
        if ws?.streamId == socket.streamId { ws = nil }
        status = "ws closed"
    }
}
