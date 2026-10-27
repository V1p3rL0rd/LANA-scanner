import SwiftUI

/// Window-local UI state. Deliberately an ObservableObject instead of `@State`:
/// in recent SDKs `@State` is a macro whose plugin (SwiftUIMacros) ships only with full Xcode,
/// so `@State` breaks builds that use Command Line Tools alone.
final class WindowState: ObservableObject {
    @Published var selection: HostInfo.ID?
    @Published var sortOrder = [KeyPathComparator(\HostInfo.ip)]
    @Published var filter = ""
    @Published var showSettings = false
}

struct ContentView: View {
    @ObservedObject var vm: ScanViewModel
    @StateObject private var ui = WindowState()

    private var displayed: [HostInfo] {
        let q = ui.filter.trimmingCharacters(in: .whitespaces).lowercased()
        let base = q.isEmpty ? vm.hosts : vm.hosts.filter { $0.matches(q) }
        return base.sorted(using: ui.sortOrder)
    }

    var body: some View {
        VStack(spacing: 0) {
            topBar
            Divider()
            HSplitView {
                HostTableView(hosts: displayed, selection: $ui.selection, sortOrder: $ui.sortOrder, vm: vm)
                    .frame(minWidth: 560, maxWidth: .infinity, maxHeight: .infinity)
                detailPane
                    .frame(minWidth: 320, idealWidth: 380, maxWidth: 560, maxHeight: .infinity)
            }
            Divider()
            StatusBar(vm: vm)
        }
        .sheet(isPresented: toolSheetBinding) {
            if let runner = vm.toolRunner { ToolOutputView(runner: runner) }
        }
        .alert("Ошибка", isPresented: errorBinding) {
            Button("OK", role: .cancel) {}
        } message: {
            Text(vm.errorMessage ?? "")
        }
    }

    // MARK: - Top bar

    private var topBar: some View {
        HStack(spacing: 8) {
            Button {
                vm.isScanning ? vm.stopScan() : vm.startScan()
            } label: {
                Label(vm.isScanning ? "Стоп" : "Сканировать",
                      systemImage: vm.isScanning ? "stop.fill" : "play.fill")
                    .frame(minWidth: 110)
            }
            .buttonStyle(.borderedProminent)
            .tint(vm.isScanning ? .red : .accentColor)
            .controlSize(.large)

            TextField("192.168.1.0/24, 10.0.0.1-50, 172.16.0.10", text: $vm.rangeText)
                .textFieldStyle(.roundedBorder)
                .font(.system(.body, design: .monospaced))
                .frame(minWidth: 240)
                .disabled(vm.isScanning)
                .onSubmit { vm.startScan() }

            Menu {
                ForEach(vm.interfaces) { iface in
                    Button(iface.label) { vm.rangeText = iface.suggestedRange }
                }
                if vm.interfaces.isEmpty { Text("Нет активных IPv4-интерфейсов") }
                Divider()
                Button("Обновить список интерфейсов") { vm.reloadInterfaces() }
            } label: {
                Label("Сеть", systemImage: "network")
            }
            .fixedSize()
            .disabled(vm.isScanning)

            Picker("Порты", selection: $vm.settings.portPreset) {
                ForEach(PortPreset.allCases) { Text($0.title).tag($0) }
            }
            .fixedSize()
            .disabled(vm.isScanning)

            Button { ui.showSettings.toggle() } label: { Image(systemName: "gearshape") }
                .help("Настройки сканирования")
                .popover(isPresented: $ui.showSettings, arrowEdge: .bottom) {
                    SettingsView(vm: vm).frame(width: 440)
                }

            Spacer(minLength: 8)

            TextField("Фильтр: IP, имя, MAC, порт", text: $ui.filter)
                .textFieldStyle(.roundedBorder)
                .frame(width: 200)
        }
        .padding(10)
    }

    // MARK: - Detail

    @ViewBuilder
    private var detailPane: some View {
        if let host = vm.host(ui.selection) {
            HostDetailView(host: host, vm: vm)
        } else {
            VStack(spacing: 8) {
                Image(systemName: "network").font(.system(size: 40)).foregroundStyle(.tertiary)
                Text("Выберите устройство").foregroundStyle(.secondary)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
    }

    // MARK: - Bindings

    private var toolSheetBinding: Binding<Bool> {
        Binding(
            get: { vm.toolRunner != nil },
            set: { presented in
                if !presented {
                    vm.toolRunner?.stop()
                    vm.toolRunner = nil
                }
            }
        )
    }

    private var errorBinding: Binding<Bool> {
        Binding(get: { vm.errorMessage != nil }, set: { if !$0 { vm.errorMessage = nil } })
    }
}

struct StatusBar: View {
    @ObservedObject var vm: ScanViewModel

    var body: some View {
        HStack(spacing: 10) {
            if vm.isScanning {
                ProgressView(value: vm.progress.fraction)
                    .frame(width: 160)
                Text(vm.progress.phase)
                if vm.progress.total > 0 {
                    Text("\(vm.progress.done) / \(vm.progress.total)")
                        .monospacedDigit()
                        .foregroundStyle(.secondary)
                }
            } else if let d = vm.lastScanDuration {
                Text(String(format: "Готово за %.1f с", d))
            } else {
                Text("Готов к сканированию")
            }
            Spacer()
            if vm.ouiUpdating {
                ProgressView().controlSize(.small)
                Text("Загрузка базы производителей…").foregroundStyle(.secondary)
            }
            Text("Устройств: \(vm.hosts.count)")
            Text("Открытых портов: \(vm.hosts.reduce(0) { $0 + $1.openPorts.count })")
        }
        .font(.callout)
        .padding(.horizontal, 12)
        .padding(.vertical, 6)
    }
}
