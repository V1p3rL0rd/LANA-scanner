import Foundation

struct ScanContext: Sendable {
    let interfaces: [NetInterface]
    let gateway: IPv4?
    let localHostName: String?
}

/// One scan run. Blocking by design — executed on a background GCD thread.
///
///  Phase 1  discovery     ARP poke ─┐
///                         ICMP echo ─┼─► alive set ─► + ARP cache read (MAC)
///                         TCP ping  ─┘   (RST counts as alive)
///  Phase 2  enrichment    vendor (OUI) · DNS / mDNS / NetBIOS names   (parallel to ports)
///  Phase 3  ports         connect() scan ─► open ports ─► banner / service probe
final class ScanJob: @unchecked Sendable {
    static let discoveryPorts: [UInt16] = [22, 80, 135, 139, 443, 445, 3389, 8080, 62078]

    private let targets: [IPv4]
    private let ports: [UInt16]
    private let discover: Bool
    private let settings: ScanSettings
    private let maxParallel: Int
    private let context: ScanContext
    private let store: ResultStore
    private let cancel: CancelFlag
    private let queue = DispatchQueue(label: "netscanner.job", qos: .userInitiated, attributes: .concurrent)

    private var timeout: Double { Double(settings.timeoutMs) / 1000 }

    init(targets: [IPv4], ports: [UInt16], discover: Bool, settings: ScanSettings,
         context: ScanContext, store: ResultStore, cancel: CancelFlag) {
        self.targets = targets
        self.ports = ports
        self.discover = discover
        self.settings = settings
        self.context = context
        self.store = store
        self.cancel = cancel
        // Keep headroom below RLIMIT_NOFILE for name lookups, pipes, the UI, etc.
        self.maxParallel = max(16, min(settings.maxParallel, Sock.currentFileLimit() - 128))
    }

    func run() {
        let targetSet = Set(targets.map(\.raw))

        if discover {
            discoverHosts(targetSet)
        } else {
            for ip in targets {
                store.update(ip) { h in
                    h.isAlive = true
                    h.openPorts = []
                    h.portsScanned = false
                }
            }
        }
        guard !cancel.isSet else { return }

        let alive = store.aliveIPs(in: targetSet)
        let names = DispatchGroup()
        if settings.resolveNames && discover {
            queue.async(group: names) { self.resolveNames(alive) }
        }
        if !ports.isEmpty && !alive.isEmpty {
            scanPorts(alive)
        }
        if names.wait(timeout: .now()) == .timedOut {
            store.setPhase("Определение имён…", total: 0)
            names.wait()
        }
        store.setPhase(cancel.isSet ? "Остановлено" : "Готово", total: 0)
    }

    // MARK: - Phase 1

    private func discoverHosts(_ targetSet: Set<UInt32>) {
        let localTargets = targets.filter { ip in context.interfaces.contains { $0.contains(ip) } }
        let probes = targets.flatMap { ip in Self.discoveryPorts.map { ProbeTarget(ip: ip, port: $0) } }
        store.setPhase("Поиск устройств…", total: probes.count)

        let group = DispatchGroup()
        queue.async(group: group) { ARPTable.poke(localTargets) }
        queue.async(group: group) {
            ICMPPinger.sweep(self.targets, timeout: max(1.0, self.timeout * 2), cancel: self.cancel) { ip, rtt in
                self.store.update(ip) { $0.markAlive(.icmp, rtt: rtt) }
            }
        }
        ConnectScanner.run(probes, timeout: timeout, maxParallel: maxParallel, cancel: cancel) { t, outcome in
            switch outcome {
            case .open(let rtt), .closed(let rtt):
                self.store.update(t.ip) { $0.markAlive(.tcp, rtt: rtt) }
            case .filtered:
                break
            }
            self.store.advance()
        }
        group.wait()
        guard !cancel.isSet else { return }

        // Give late ARP replies a moment, then harvest the kernel ARP cache.
        usleep(300_000)
        let arp = ARPTable.read()
        for (raw, mac) in arp where targetSet.contains(raw) {
            store.update(IPv4(raw: raw)) { h in
                h.markAlive(.arp, rtt: nil)
                h.mac = mac
            }
        }

        // This Mac is never in its own ARP cache.
        for iface in context.interfaces where targetSet.contains(iface.address.raw) {
            store.update(iface.address) { h in
                h.markAlive(.local, rtt: 0)
                h.isLocalMachine = true
                h.mac = h.mac ?? iface.mac
                if h.dnsName == nil { h.dnsName = self.context.localHostName }
            }
        }
        if let gw = context.gateway, targetSet.contains(gw.raw) {
            store.update(gw) { $0.isGateway = $0.isAlive }
        }
        for ip in store.aliveIPs(in: targetSet) {
            store.update(ip) { h in
                if let mac = h.mac { h.vendor = OUIDatabase.shared.vendor(for: mac) }
            }
        }
    }

    // MARK: - Phase 2

    private enum Lookup: CaseIterable { case dns, mdns, netbios }

    private func resolveNames(_ ips: [IPv4]) {
        // Flattened (host × method) work items: no nested waits, no thread starvation.
        let items = ips.flatMap { ip in Lookup.allCases.map { (ip, $0) } }
        parallelForEach(items, maxConcurrent: 24, cancel: cancel) { item in
            let (ip, kind) = item
            switch kind {
            case .dns:
                if let n = NameResolver.reverseDNS(ip) {
                    self.store.update(ip) { h in if !h.isLocalMachine { h.dnsName = n } }
                }
            case .mdns:
                if let n = NameResolver.mdnsName(ip, timeout: 1.0) {
                    self.store.update(ip) { $0.mdnsName = n }
                }
            case .netbios:
                if let nb = NameResolver.netbios(ip, timeout: 1.0) {
                    self.store.update(ip) { h in
                        h.netbiosName = nb.name
                        h.workgroup = nb.group
                        if h.mac == nil, let m = nb.mac {
                            h.mac = m
                            h.vendor = OUIDatabase.shared.vendor(for: m)
                        }
                    }
                }
            }
        }
    }

    // MARK: - Phase 3

    private func scanPorts(_ hosts: [IPv4]) {
        let probes = hosts.flatMap { ip in ports.map { ProbeTarget(ip: ip, port: $0) } }
        store.setPhase("Сканирование портов…", total: probes.count)

        var open: [ProbeTarget] = []
        ConnectScanner.run(probes, timeout: timeout, maxParallel: maxParallel, cancel: cancel) { t, outcome in
            if case .open = outcome {
                open.append(t)
                self.store.update(t.ip) { h in
                    h.openPorts.append(PortResult(port: t.port, service: ServiceDB.name(for: t.port)))
                    h.openPorts.sort { $0.port < $1.port }
                }
            }
            self.store.advance()
        }
        for ip in hosts { store.update(ip) { $0.portsScanned = true } }

        guard settings.grabBanners, !open.isEmpty, !cancel.isSet else { return }
        store.setPhase("Определение сервисов…", total: open.count)
        let probeTimeout = max(1.5, timeout)
        parallelForEach(open, maxConcurrent: 16, cancel: cancel) { t in
            let r = ServiceProbe.probe(t.ip, port: t.port, timeout: probeTimeout)
            self.store.update(t.ip) { h in
                guard let i = h.openPorts.firstIndex(where: { $0.port == t.port }) else { return }
                if let s = r.service { h.openPorts[i].service = s }
                h.openPorts[i].banner = r.banner
            }
            self.store.advance()
        }
    }
}
