// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "TVWatch",
    platforms: [.macOS(.v14)],
    targets: [
        .executableTarget(name: "TVWatch", path: "Sources/TVWatch")
    ],
    swiftLanguageModes: [.v5]
)
