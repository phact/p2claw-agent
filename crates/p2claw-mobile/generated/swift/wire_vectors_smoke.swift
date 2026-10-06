/*
 * Smoke test: drives the UniFFI-generated Swift codec against
 * `crates/wire/test-vectors.json`. Same fixture the TS bootstrap
 * and Rust wire crate use — green here means three implementations
 * agree on every byte of every supported frame.
 *
 * Run from the repo root (requires Swift toolchain; on macOS the
 * built-in `swift` works, on Linux install swift.org's release):
 *
 *   swift build  # in mobile/ios/sdk once that lands; for this smoke
 *                # test, link manually:
 *   swiftc \
 *       crates/p2claw-mobile/generated/swift/p2claw_mobile.swift \
 *       crates/p2claw-mobile/generated/swift/wire_vectors_smoke.swift \
 *       -I crates/p2claw-mobile/generated/swift \
 *       -L target/debug \
 *       -lp2claw_mobile \
 *       -o /tmp/p2claw-mobile-smoke
 *   ./tmp/p2claw-mobile-smoke
 */

import Foundation

guard let fixtureData = try? String(contentsOfFile: "crates/wire/test-vectors.json") else {
    fatalError("could not read wire-vectors.json from repo root")
}

let pattern = #"\{[^{}]*?"name":\s*"([^"]+)"[^{}]*?"hex":\s*"([^"]+)"[^{}]*?\}"#
let regex = try NSRegularExpression(pattern: pattern)
let range = NSRange(fixtureData.startIndex..., in: fixtureData)
let matches = regex.matches(in: fixtureData, range: range)

precondition(!matches.isEmpty, "fixture must carry vectors")

for match in matches {
    let name = String(fixtureData[Range(match.range(at: 1), in: fixtureData)!])
    let hex = String(fixtureData[Range(match.range(at: 2), in: fixtureData)!])

    var bytes = Data(capacity: hex.count / 2)
    var idx = hex.startIndex
    while idx < hex.endIndex {
        let next = hex.index(idx, offsetBy: 2)
        bytes.append(UInt8(hex[idx..<next], radix: 16)!)
        idx = next
    }

    let decoder = Decoder()
    decoder.push(bytes: bytes)
    guard let frame = try? decoder.nextFrame() else {
        fatalError("vector '\(name)': decoder threw on full frame")
    }
    guard let unwrapped = frame else {
        fatalError("vector '\(name)': decoder returned nil on full frame")
    }
    precondition(decoder.buffered() == 0, "vector '\(name)': decoder left bytes buffered")

    let reEncoded = encodeFrame(frame: unwrapped)
    precondition(reEncoded == bytes, "vector '\(name)': re-encoded bytes diverge from fixture")
}

print("OK: \(matches.count) wire vectors round-trip through Swift bindings.")
