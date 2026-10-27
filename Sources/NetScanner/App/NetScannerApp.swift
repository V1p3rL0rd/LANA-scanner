import AppKit
import SwiftUI

@main
struct NetScannerApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate
    @StateObject private var vm = ScanViewModel()

    var body: some Scene {
        WindowGroup("LANA Scanner") {
            ContentView(vm: vm)
                .frame(minWidth: 980, minHeight: 560)
        }
        .commands {
            CommandMenu("Scan") {
                Button("Start Scan") { vm.startScan() }
                    .keyboardShortcut("r")
                    .disabled(vm.isScanning)
                Button("Stop Scan") { vm.stopScan() }
                    .keyboardShortcut(".")
                    .disabled(!vm.isScanning)
                Divider()
                Button("Refresh Interfaces") { vm.reloadInterfaces() }
                Button("Update Vendor Database") { Task { await vm.updateOUI() } }
            }
        }

        Settings {
            SettingsView(vm: vm)
                .frame(width: 460)
                .padding(.vertical)
        }
    }
}

final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) {
        // A write to a socket the peer already reset must not kill the app.
        signal(SIGPIPE, SIG_IGN)
        Sock.raiseFileDescriptorLimit()
        // Needed when launched as a bare binary via `swift run` (no .app bundle).
        NSApp.setActivationPolicy(.regular)
        NSApp.activate(ignoringOtherApps: true)
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { true }
}
