import AppKit
import SwiftUI

final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.regular)
        NSApp.activate(ignoringOtherApps: true)
    }
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { true }
}

@main
struct TVWatchApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) var delegate
    @StateObject private var store = Store()

    var body: some Scene {
        WindowGroup("TV Watch") {
            ContentView()
                .environmentObject(store)
                .task {
                    store.connect()
                    // при каждом открытии — обновить подписку (когда Pi подключится)
                    for _ in 0..<40 where store.state != .ready { try? await Task.sleep(for: .milliseconds(250)) }
                    if store.state == .ready { store.refreshSubscription() }
                }
        }
        .commands {
            CommandGroup(after: .newItem) {
                Button("Обновить подписку") { store.refreshSubscription() }.keyboardShortcut("r")
                Button("Переподключиться к Pi") { store.connect() }.keyboardShortcut("r", modifiers: [.command, .shift])
            }
        }
    }
}
