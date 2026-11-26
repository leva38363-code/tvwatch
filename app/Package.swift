// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "TVWatch",
    platforms: [.macOS("26.0")],
    targets: [
        .executableTarget(name: "TVWatch", path: "Sources/TVWatch")
    ],
    swiftLanguageModes: [.v5]
)
