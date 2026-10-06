// swift-tools-version: 5.10
//
// P2clawSDK — Swift package for the p2claw mobile SDK.
//
// Three targets:
//
//   - `P2clawMobileCoreRS` — binary xcframework holding the Rust
//     `p2claw-mobile` crate compiled for ios-device + ios-sim. Built
//     by `../build-rust-xcframework.sh` (macOS only).
//   - `UniFFI` — generated Swift bindings (`p2claw_mobile.swift`)
//     that bridge into the binary target's C ABI. The build script
//     repopulates `Sources/UniFFI/` on every xcframework rebuild.
//   - `P2clawSDK` — hand-written ergonomic API + WebRTC integration.
//
// To build locally:
//   1. Run `../build-rust-xcframework.sh` (macOS).
//   2. `swift build`.
//
// CI runs both steps on `macos-14`.

import PackageDescription

let package = Package(
    name: "P2clawSDK",
    platforms: [.iOS(.v16)],
    products: [
        .library(name: "P2clawSDK", targets: ["P2clawSDK"]),
    ],
    dependencies: [
        // LiveKit's prebuilt WebRTC.xcframework — the maintained
        // replacement for Google's stale `WebRTC.framework`. Types are
        // LK-prefixed (`LKRTCPeerConnection` etc.) so they don't clash
        // with Google's WebRTC.framework if both are linked. Pin the
        // tag at release time; bump along with the Android sibling so
        // the two SDK halves stay on the same WebRTC build.
        .package(
            url: "https://github.com/livekit/webrtc-xcframework",
            from: "144.7559.10"
        ),
    ],
    targets: [
        .binaryTarget(
            name: "P2clawMobileCoreRS",
            path: "P2clawMobileCoreRS.xcframework"
        ),
        .target(
            name: "UniFFI",
            dependencies: ["P2clawMobileCoreRS"],
            path: "Sources/UniFFI"
        ),
        .target(
            name: "P2clawSDK",
            dependencies: [
                "UniFFI",
                .product(name: "LiveKitWebRTC", package: "webrtc-xcframework"),
            ],
            path: "Sources/P2clawSDK"
        ),
        .testTarget(
            name: "P2clawSDKTests",
            dependencies: ["P2clawSDK"],
            path: "Tests/P2clawSDKTests"
        ),
    ]
)
