#!/usr/bin/env bash
# Cross-compile crates/p2claw-mobile to the three iOS targets, fat-bind
# the two simulator slices, and assemble the result into an
# .xcframework that mobile/ios/sdk/Package.swift's binaryTarget points at.
#
# Must run on macOS (xcodebuild + lipo are Apple-only). On CI this runs
# on a macos-14 GitHub Actions runner.
#
# Requirements:
#   - Xcode command-line tools (`xcode-select --install`)
#   - rustup with the three iOS targets installed
#       (aarch64-apple-ios, aarch64-apple-ios-sim, x86_64-apple-ios)
#
# Env overrides:
#   PROFILE   release | debug   (default: release)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
CRATE_DIR="${REPO_ROOT}/crates/p2claw-mobile"
SDK_DIR="${SCRIPT_DIR}/sdk"
TARGET_DIR="${REPO_ROOT}/target"

PROFILE="${PROFILE:-release}"
PROFILE_DIR="$PROFILE"

if [[ "$(uname -s)" != "Darwin" ]]; then
    echo "iOS xcframework build requires macOS (xcodebuild, lipo)" >&2
    exit 1
fi

PROFILE_FLAG=""
if [[ "$PROFILE" == "release" ]]; then
    PROFILE_FLAG="--release"
fi

cd "$CRATE_DIR"

# Compile the three iOS static libraries.
for t in aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios; do
    echo "==> cargo build --target $t"
    cargo build $PROFILE_FLAG --target "$t" -p p2claw-mobile
done

# Generate the Swift wrapper + C header + module map for the xcframework.
# `uniffi-bindgen` invocation uses the device-arch static lib as the
# introspection source.
STAGING="${TARGET_DIR}/uniffi-xcframework-staging"
rm -rf "$STAGING"
mkdir -p "$STAGING"

cargo run --bin uniffi-bindgen -- generate \
    --library "${TARGET_DIR}/aarch64-apple-ios/${PROFILE_DIR}/libp2claw_mobile.a" \
    --language swift \
    --out-dir "$STAGING"

# Move the generated Swift wrapper into the SwiftPM target dir; headers
# + modulemap stay in staging and get bundled into the xcframework via
# `xcodebuild -headers`.
mkdir -p "${SDK_DIR}/Sources/UniFFI"
mv "$STAGING"/*.swift "${SDK_DIR}/Sources/UniFFI/"

# Fat-bind the two simulator slices into one .a so xcodebuild accepts
# it as a single library entry. xcframework rejects multiple libraries
# for the same platform variant.
SIM_FAT="${TARGET_DIR}/ios-sim-fat-${PROFILE_DIR}"
mkdir -p "$SIM_FAT"
lipo -create \
    "${TARGET_DIR}/aarch64-apple-ios-sim/${PROFILE_DIR}/libp2claw_mobile.a" \
    "${TARGET_DIR}/x86_64-apple-ios/${PROFILE_DIR}/libp2claw_mobile.a" \
    -output "${SIM_FAT}/libp2claw_mobile.a"

# Assemble the xcframework. Output overwrites any existing .xcframework
# at the target path (xcodebuild refuses to overwrite, so we rm first).
XCF_OUT="${SDK_DIR}/P2clawMobileCoreRS.xcframework"
rm -rf "$XCF_OUT"
xcodebuild -create-xcframework \
    -library "${TARGET_DIR}/aarch64-apple-ios/${PROFILE_DIR}/libp2claw_mobile.a" \
        -headers "$STAGING" \
    -library "${SIM_FAT}/libp2claw_mobile.a" \
        -headers "$STAGING" \
    -output "$XCF_OUT"

echo "Built $XCF_OUT"
