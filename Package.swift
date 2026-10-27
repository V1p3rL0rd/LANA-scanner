// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "NetScanner",
    platforms: [.macOS(.v13)],
    targets: [
        .executableTarget(
            name: "NetScanner",
            path: "Sources/NetScanner"
        ),
        .testTarget(
            name: "NetScannerTests",
            dependencies: ["NetScanner"],
            path: "Tests/NetScannerTests"
        ),
    ]
)
