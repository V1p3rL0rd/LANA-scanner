import SwiftUI

struct SettingsView: View {
    @ObservedObject var vm: ScanViewModel

    private var portSummary: String {
        if vm.settings.portPreset == .none { return String(localized: "Device discovery only") }
        guard let ports = try? vm.settings.ports() else { return String(localized: "Error in port list") }
        let summary = String(localized: "Ports per host: \(ports.count)")
        return ports.count > 5_000 ? summary + " — " + String(localized: "slow on large ranges") : summary
    }

    var body: some View {
        Form {
            Section("Ports") {
                Picker("Preset", selection: $vm.settings.portPreset) {
                    ForEach(PortPreset.allCases) { Text($0.title).tag($0) }
                }
                if vm.settings.portPreset == .custom {
                    TextField("List", text: $vm.settings.customPorts, prompt: Text("22,80,443,8000-8100"))
                        .font(.system(.body, design: .monospaced))
                }
                Text(portSummary).font(.caption).foregroundStyle(.secondary)
            }

            Section("Performance") {
                Stepper(value: $vm.settings.timeoutMs, in: 100...5_000, step: 100) {
                    Text("Connection timeout: \(vm.settings.timeoutMs) ms")
                }
                Stepper(value: $vm.settings.maxParallel, in: 32...4_096, step: 32) {
                    Text("Parallel connections: \(vm.settings.maxParallel)")
                }
                Text("On Wi-Fi and slow networks raise the timeout to 1500–2000 ms.")
                    .font(.caption).foregroundStyle(.secondary)
            }

            Section("Extras") {
                Toggle("Resolve names (DNS, mDNS, NetBIOS)", isOn: $vm.settings.resolveNames)
                Toggle("Detect services and versions (banners)", isOn: $vm.settings.grabBanners)
            }

            Section("Vendor Database (IEEE OUI)") {
                HStack {
                    if vm.ouiCount > 0 { Text("Entries: \(vm.ouiCount)") } else { Text("Not loaded") }
                    Spacer()
                    if vm.ouiUpdating { ProgressView().controlSize(.small) }
                    Button("Update") { Task { await vm.updateOUI() } }
                        .disabled(vm.ouiUpdating)
                }
            }
        }
        .formStyle(.grouped)
    }
}

struct ToolOutputView: View {
    @ObservedObject var runner: ToolRunner
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Text(runner.title).font(.headline)
                Spacer()
                if runner.isRunning {
                    ProgressView().controlSize(.small)
                    Button("Stop") { runner.stop() }
                }
                Button("Close") {
                    runner.stop()
                    dismiss()
                }
                .keyboardShortcut(.cancelAction)
            }
            ScrollViewReader { proxy in
                ScrollView {
                    VStack(alignment: .leading, spacing: 0) {
                        Text(runner.output)
                            .font(.system(.body, design: .monospaced))
                            .textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .leading)
                        Color.clear.frame(height: 1).id("end")
                    }
                    .padding(8)
                }
                .background(Color(nsColor: .textBackgroundColor))
                .onChange(of: runner.output) { _ in proxy.scrollTo("end", anchor: .bottom) }
            }
        }
        .padding()
        .frame(minWidth: 640, minHeight: 400)
    }
}
