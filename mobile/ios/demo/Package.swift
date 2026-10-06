// swift-tools-version: 5.10
//
// P2clawDemo — minimal SwiftUI app exercising the SDK.
//
// Connects to a box, opens a WebSocket, and shows
// round-tripped messages. Built as a standalone Swift package for
// `swift run`-able iteration; for App Store distribution the
// `P2clawDemo` target gets dropped into an Xcode project.

import PackageDescription

let package = Package(
    name: "P2clawDemo",
    platforms: [.iOS(.v16)],
    products: [
        .executable(name: "P2clawDemo", targets: ["P2clawDemo"]),
    ],
    dependencies: [
        .package(path: "../sdk"),
    ],
    targets: [
        .executableTarget(
            name: "P2clawDemo",
            dependencies: [
                .product(name: "P2clawSDK", package: "sdk"),
            ],
            path: "Sources/P2clawDemo"
        ),
    ]
)
