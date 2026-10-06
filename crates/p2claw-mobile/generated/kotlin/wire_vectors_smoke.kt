/*
 * Smoke test: drives the UniFFI-generated Kotlin codec against
 * `crates/wire/test-vectors.json`. Three implementations end up
 * agreeing on every byte: the TS bootstrap, the Rust box-side wire
 * crate, and (via this script) the mobile SDK's Kotlin bindings.
 *
 * Run from the repo root (requires JVM + Kotlin toolchain):
 *
 *   kotlinc \
 *       crates/p2claw-mobile/generated/kotlin/uniffi/p2claw_mobile/p2claw_mobile.kt \
 *       crates/p2claw-mobile/generated/kotlin/wire_vectors_smoke.kt \
 *       -classpath ~/.m2/repository/net/java/dev/jna/jna/5.14.0/jna-5.14.0.jar \
 *       -include-runtime -d /tmp/p2claw-mobile-smoke.jar
 *   java -Djava.library.path=target/debug \
 *       -classpath ~/.m2/repository/net/java/dev/jna/jna/5.14.0/jna-5.14.0.jar:/tmp/p2claw-mobile-smoke.jar \
 *       WireVectorsSmokeKt
 *
 * The library path must point at the built `libp2claw_mobile.so`
 * (cdylib artifact from `cargo build -p p2claw-mobile`).
 */

import uniffi.p2claw_mobile.Decoder
import uniffi.p2claw_mobile.encodeFrame
import java.io.File

fun main() {
    val fixture = File("crates/wire/test-vectors.json").readText()

    // Pull each vector's hex; the rest of the JSON is descriptive metadata.
    val entries = Regex("""\{[^{}]*?"name":\s*"([^"]+)"[^{}]*?"hex":\s*"([^"]+)"[^{}]*?\}""")
        .findAll(fixture)
        .map { it.groupValues[1] to it.groupValues[2] }
        .toList()

    require(entries.isNotEmpty()) { "fixture must carry vectors" }

    for ((name, hex) in entries) {
        val bytes = hex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()

        val decoder = Decoder()
        decoder.push(bytes.toUByteArray().toList().toUByteArray().toByteArray())
        val frame = decoder.nextFrame()
            ?: error("vector '$name': decoder returned null on full frame")
        require(decoder.buffered() == 0u) {
            "vector '$name': decoder left ${decoder.buffered()} bytes buffered"
        }

        val reEncoded = encodeFrame(frame)
        require(reEncoded.contentEquals(bytes)) {
            "vector '$name': re-encoded bytes diverge from fixture"
        }
    }

    println("OK: ${entries.size} wire vectors round-trip through Kotlin bindings.")
}
