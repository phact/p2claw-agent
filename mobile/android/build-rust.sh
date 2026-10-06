#!/usr/bin/env bash
# Cross-compile crates/p2claw-mobile to the four Android ABIs and lay the
# resulting libp2claw_mobile.so files into mobile/android/sdk/src/main/jniLibs/
# in the layout AGP expects (`<abi>/lib*.so`).
#
# Run from anywhere — the script resolves paths relative to itself.
#
# Requirements:
#   - rustup with the four android targets installed
#       (aarch64-linux-android, armv7-linux-androideabi,
#        x86_64-linux-android, i686-linux-android)
#   - cargo-ndk (`cargo install cargo-ndk`)
#   - Android NDK r25+ available via ANDROID_NDK_HOME or
#     ANDROID_NDK_ROOT (CI provides this via nttld/setup-ndk@v1)
#
# Env overrides:
#   PROFILE   release | debug   (default: release)
#   ABIS      space-separated list of Android ABIs (default: all four)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
CRATE_DIR="${REPO_ROOT}/crates/p2claw-mobile"
OUT_DIR="${SCRIPT_DIR}/sdk/src/main/jniLibs"

PROFILE="${PROFILE:-release}"
ABIS="${ABIS:-arm64-v8a armeabi-v7a x86_64 x86}"

if ! command -v cargo-ndk >/dev/null; then
    echo "cargo-ndk not installed. Run: cargo install cargo-ndk" >&2
    exit 1
fi

if [[ -z "${ANDROID_NDK_HOME:-}" && -z "${ANDROID_NDK_ROOT:-}" ]]; then
    echo "ANDROID_NDK_HOME or ANDROID_NDK_ROOT must be set" >&2
    exit 1
fi

mkdir -p "$OUT_DIR"

# Build the `-t <abi>` args for cargo-ndk in one shot. cargo-ndk handles
# the NDK toolchain + linker config; no per-target CARGO_TARGET_*_LINKER
# fiddling needed.
ABI_FLAGS=()
for abi in $ABIS; do
    ABI_FLAGS+=("-t" "$abi")
done

PROFILE_FLAG=""
if [[ "$PROFILE" == "release" ]]; then
    PROFILE_FLAG="--release"
fi

cd "$CRATE_DIR"
cargo ndk \
    "${ABI_FLAGS[@]}" \
    -o "$OUT_DIR" \
    build $PROFILE_FLAG -p p2claw-mobile

echo "Built libp2claw_mobile.so for ABIs: $ABIS"
echo "Output: $OUT_DIR/<abi>/libp2claw_mobile.so"
