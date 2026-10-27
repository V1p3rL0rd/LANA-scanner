import SwiftUI

struct SettingsView: View {
    @ObservedObject var vm: ScanViewModel

    private var portSummary: String {
        if vm.settings.portPreset == .none { return "Только обнаружение устройств" }
        guard let ports = try? vm.settings.ports() else { return "Ошибка в списке портов" }
        let note = ports.count > 5_000 ? " — медленно на больших диапазонах" : ""
        return "\(ports.count) портов на хост\(note)"
    }

    var body: some View {
        Form {
            Section("Порты") {
                Picker("Набор", selection: $vm.settings.portPreset) {
                    ForEach(PortPreset.allCases) { Text($0.title).tag($0) }
                }
                if vm.settings.portPreset == .custom {
                    TextField("Список", text: $vm.settings.customPorts, prompt: Text("22,80,443,8000-8100"))
                        .font(.system(.body, design: .monospaced))
                }
                Text(portSummary).font(.caption).foregroundStyle(.secondary)
            }

            Section("Производительность") {
                Stepper(value: $vm.settings.timeoutMs, in: 100...5_000, step: 100) {
                    Text("Таймаут соединения: \(vm.settings.timeoutMs) мс")
                }
                Stepper(value: $vm.settings.maxParallel, in: 32...4_096, step: 32) {
                    Text("Параллельных соединений: \(vm.settings.maxParallel)")
                }
                Text("Для Wi-Fi и медленных сетей увеличьте таймаут до 1500–2000 мс.")
                    .font(.caption).foregroundStyle(.secondary)
            }

            Section("Дополнительно") {
                Toggle("Определять имена (DNS, mDNS, NetBIOS)", isOn: $vm.settings.resolveNames)
                Toggle("Определять сервисы и версии (баннеры)", isOn: $vm.settings.grabBanners)
            }

            Section("База производителей (IEEE OUI)") {
                HStack {
                    Text(vm.ouiCount > 0 ? "\(vm.ouiCount) записей" : "Не загружена")
                    Spacer()
                    if vm.ouiUpdating { ProgressView().controlSize(.small) }
                    Button("Обновить") { Task { await vm.updateOUI() } }
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
                    Button("Стоп") { runner.stop() }
                }
                Button("Закрыть") {
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
