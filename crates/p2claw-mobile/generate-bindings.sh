#!/usr/bin/env bash
# Regenerate Kotlin + Swift bindings from the current Rust surface and
# (when the platform toolchains are present) run the wire-vectors
# smoke tests against the generated code.
#
# Run from the workspace root:
#   ./crates/p2claw-mobile/generate-bindings.sh
#
# Requires: cargo. Optional (for smoke tests): kotlinc + java + jna,
# and/or swiftc.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CRATE_DIR="${ROOT}/crates/p2claw-mobile"
OUT_KT="${CRATE_DIR}/generated/kotlin"
OUT_SWIFT="${CRATE_DIR}/generated/swift"

cd "$ROOT"

case "$(uname -s)" in
    Darwin) LIB_EXT="dylib" ;;
    Linux)  LIB_EXT="so" ;;
    *)      echo "unsupported host OS: $(uname -s)" >&2; exit 1 ;;
esac

echo "==> building p2claw-mobile cdylib"
cargo build -p p2claw-mobile

LIB_PATH="${ROOT}/target/debug/libp2claw_mobile.${LIB_EXT}"
test -f "$LIB_PATH" || { echo "missing cdylib at $LIB_PATH" >&2; exit 1; }

echo "==> generating Kotlin bindings → $OUT_KT"
mkdir -p "$OUT_KT"
cargo run --bin uniffi-bindgen -- generate \
    --library "$LIB_PATH" \
    --language kotlin \
    --out-dir "$OUT_KT"

echo "==> generating Swift bindings → $OUT_SWIFT"
mkdir -p "$OUT_SWIFT"
cargo run --bin uniffi-bindgen -- generate \
    --library "$LIB_PATH" \
    --language swift \
    --out-dir "$OUT_SWIFT"

# --- Optional smoke-test invocations ----------------------------------

if command -v kotlinc >/dev/null && command -v java >/dev/null; then
    JNA_JAR="${JNA_JAR:-$HOME/.m2/repository/net/java/dev/jna/jna/5.14.0/jna-5.14.0.jar}"
    if [[ -f "$JNA_JAR" ]]; then
        echo "==> compiling + running Kotlin smoke test"
        JAR="$(mktemp -d)/p2claw-mobile-smoke.jar"
        kotlinc \
            "$OUT_KT/uniffi/p2claw_mobile/p2claw_mobile.kt" \
            "$OUT_KT/wire_vectors_smoke.kt" \
            -classpath "$JNA_JAR" \
            -include-runtime -d "$JAR"
        java -Djava.library.path="${ROOT}/target/debug" \
            -classpath "$JNA_JAR:$JAR" \
            WireVectorsSmokeKt
    else
        echo "(skip Kotlin smoke: JNA jar not found at $JNA_JAR — set JNA_JAR)"
    fi
else
    echo "(skip Kotlin smoke: kotlinc / java not on PATH)"
fi

if command -v swiftc >/dev/null; then
    echo "==> compiling + running Swift smoke test"
    BIN="$(mktemp -d)/p2claw-mobile-smoke"
    swiftc \
        "$OUT_SWIFT/p2claw_mobile.swift" \
        "$OUT_SWIFT/wire_vectors_smoke.swift" \
        -I "$OUT_SWIFT" \
        -L "${ROOT}/target/debug" \
        -lp2claw_mobile \
        -o "$BIN"
    DYLD_LIBRARY_PATH="${ROOT}/target/debug" \
    LD_LIBRARY_PATH="${ROOT}/target/debug" \
        "$BIN"
else
    echo "(skip Swift smoke: swiftc not on PATH)"
fi
