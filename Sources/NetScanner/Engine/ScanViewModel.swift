import AppKit
import Foundation
import SystemConfiguration

@MainActor
final class ScanViewModel: ObservableObject {
    @Published var rangeText = ""
    @Published var settings = ScanSettings.load() { didSet { settings.save() } }
    @Published var errorMessage: String?
    @Published var toolRunner: ToolRunner?

    @Published private(set) var hosts: [HostInfo] = []
    @Published private(set) var progress = ScanProgress()
    @Published private(set) var isScanning = false
    @Published private(set) var interfaces: [NetInterface] = []
    @Published private(set) var gateway: IPv4?
    @Published private(set) var ouiCount = 0
    @Published private(set) var ouiUpdating = false
    @Published private(set) var lastScanDuration: TimeInterval?

    private let store = ResultStore()
    private var cancelFlag = CancelFlag()
    private var lastVersion = -1
    private var startedAt = Date()

    init() {
        reloadInterfaces()
        startRefreshLoop()
        Task { await self.loadOUI() }
    }

    // MARK: - Network context

    func reloadInterfaces() {
        interfaces = Interfaces.list()
        let route = Interfaces.defaultRoute()
        gateway = route.gateway
        if rangeText.isEmpty {
            let preferred = interfaces.first { $0.name == route.interface } ?? interfaces.first
            rangeText = preferred?.suggestedRange ?? ""
        }
    }

    private var context: ScanContext {
        let local = SCDynamicStoreCopyLocalHostName(nil).map { ($0 as String) + ".local" }
        return ScanContext(interfaces: interfaces, gateway: gateway, localHostName: local)
    }

    // MARK: - Scanning

    func startScan() {
        guard !isScanning else { return }
        let targets: [IPv4]
        let ports: [UInt16]
        do {
            targets = try TargetParser.parse(rangeText)
            ports = try settings.ports()
        } catch {
            errorMessage = error.localizedDescription
            return
        }
        store.reset()
        lastVersion = -1
        let flag = CancelFlag()
        launch(ScanJob(targets: targets, ports: ports, discover: true, settings: settings,
                       context: context, store: store, cancel: flag), flag: flag)
    }

    func rescanPorts(_ host: HostInfo) {
        guard !isScanning else { return }
        var ports = (try? settings.ports()) ?? []
        if ports.isEmpty { ports = (try? PortSpec.parse(PortData.top1000)) ?? [] }
        let flag = CancelFlag()
        launch(ScanJob(targets: [host.ip], ports: ports, discover: false, settings: settings,
                       context: context, store: store, cancel: flag), flag: flag)
    }

    func stopScan() { cancelFlag.set() }

    private func launch(_ job: ScanJob, flag: CancelFlag) {
        cancelFlag = flag
        isScanning = true
        startedAt = Date()
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            job.run()
            Task { @MainActor [weak self] in self?.jobFinished() }
        }
    }

    private func jobFinished() {
        isScanning = false
        lastScanDuration = Date().timeIntervalSince(startedAt)
        refresh()
    }

    private func startRefreshLoop() {
        Task { [weak self] in
            while !Task.isCancelled {
                guard let vm = self else { return }
                vm.refresh()
                try? await Task.sleep(nanoseconds: 300_000_000)
            }
        }
    }

    private func refresh() {
        guard let snap = store.snapshot(since: lastVersion) else { return }
        lastVersion = snap.version
        hosts = snap.hosts
        progress = snap.progress
    }

    func host(_ id: HostInfo.ID?) -> HostInfo? {
        guard let id else { return nil }
        return hosts.first { $0.id == id }
    }

    // MARK: - Vendor DB

    private func loadOUI() async {
        let count = await Task.detached { OUIDatabase.shared.loadedCount() }.value
        ouiCount = count
        if count == 0 { await updateOUI(silent: true) }
    }

    func updateOUI(silent: Bool = false) async {
        guard !ouiUpdating else { return }
        ouiUpdating = true
        defer { ouiUpdating = false }
        do {
            ouiCount = try await OUIDatabase.shared.update()
            store.reapplyVendors()
        } catch {
            if !silent {
                errorMessage = "Не удалось обновить базу производителей: \(error.localizedDescription)"
            }
        }
    }

    // MARK: - Host actions

    func open(_ url: URL) { NSWorkspace.shared.open(url) }

    func copy(_ text: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
    }

    func wake(_ host: HostInfo) {
        guard let mac = host.mac else { return }
        let broadcasts = interfaces.filter { $0.contains(host.ip) }.map(\.broadcast)
        if !WakeOnLAN.send(mac: mac, broadcasts: broadcasts) {
            errorMessage = "Не удалось отправить Wake-on-LAN пакет на \(mac)"
        }
    }

    func ping(_ host: HostInfo) {
        runTool("ping \(host.ip)", "/sbin/ping", ["-c", "10", host.ip.description])
    }

    func traceroute(_ host: HostInfo) {
        runTool("traceroute \(host.ip)", "/usr/sbin/traceroute",
                ["-n", "-w", "1", "-q", "1", "-m", "30", host.ip.description])
    }

    private func runTool(_ title: String, _ path: String, _ args: [String]) {
        toolRunner?.stop()
        let runner = ToolRunner(title: title, path: path, args: args)
        toolRunner = runner
        runner.start()
    }
}
