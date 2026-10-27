import Foundation

enum DiscoveryMethod: String, Codable, CaseIterable, Hashable, Sendable {
    case local = "Local"
    case icmp = "ICMP"
    case tcp = "TCP"
    case arp = "ARP"

    var title: String { self == .local ? String(localized: "This Mac") : rawValue }
}

struct PortResult: Identifiable, Hashable, Sendable {
    let port: UInt16
    var service: String
    var banner: String?
    var id: UInt16 { port }
}

struct HostInfo: Identifiable, Hashable, Sendable {
    let ip: IPv4
    var id: UInt32 { ip.raw }

    var isAlive = false
    var methods: Set<DiscoveryMethod> = []
    var rttMs: Double?
    var mac: String?
    var vendor: String?
    var dnsName: String?
    var mdnsName: String?
    var netbiosName: String?
    var workgroup: String?
    var isLocalMachine = false
    var isGateway = false
    var openPorts: [PortResult] = []
    var portsScanned = false

    init(ip: IPv4) { self.ip = ip }

    mutating func markAlive(_ method: DiscoveryMethod, rtt: Double?) {
        isAlive = true
        methods.insert(method)
        if let rtt, rtt < (rttMs ?? .infinity) { rttMs = rtt }
    }

    // MARK: - Presentation / sort keys (non-optional so they work with KeyPathComparator)

    var displayName: String { dnsName ?? mdnsName ?? netbiosName ?? "" }
    var vendorSort: String { vendor ?? "" }
    var macSort: String { mac ?? "" }
    var openPortCount: Int { openPorts.count }
    var rttSort: Double { rttMs ?? .infinity }
    var statusRank: Int { isLocalMachine ? 0 : (isGateway ? 1 : (onlyARP ? 3 : 2)) }

    /// Answered nothing but ARP: firewalled host, or a stale ARP cache entry (macOS keeps them ~20 min).
    var onlyARP: Bool { methods == [.arp] }

    var symbolName: String {
        if isLocalMachine { return "laptopcomputer" }
        if isGateway { return "network" }
        return "circle.fill"
    }

    var portsSummary: String {
        if openPorts.isEmpty { return portsScanned ? "—" : "" }
        return openPorts.map { String($0.port) }.joined(separator: ", ")
    }

    var rttText: String {
        guard let r = rttMs else { return "" }
        return r < 1 ? String(localized: "<1 ms") : String(localized: "\(String(format: "%.0f", r)) ms")
    }

    func matches(_ query: String) -> Bool {
        if ip.description.contains(query) { return true }
        let haystack = [displayName, mac ?? "", vendor ?? "", workgroup ?? ""]
            .joined(separator: " ").lowercased()
        if haystack.contains(query) { return true }
        return openPorts.contains { String($0.port) == query || $0.service.lowercased().contains(query) }
    }
}

struct ScanProgress: Equatable, Sendable {
    var phase = ""
    var done = 0
    var total = 0
    var fraction: Double { total > 0 ? min(1, Double(done) / Double(total)) : 0 }
}
