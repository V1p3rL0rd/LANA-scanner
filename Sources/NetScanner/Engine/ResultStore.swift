import Foundation

/// Lock-protected scan results. Workers write from many threads; the UI polls
/// `snapshot(since:)` a few times per second, so the main thread is never flooded.
final class ResultStore: @unchecked Sendable {
    private let lock = NSLock()
    private var hosts: [UInt32: HostInfo] = [:]
    private var progress = ScanProgress()
    private var version = 0

    func reset() {
        lock.lock(); defer { lock.unlock() }
        hosts.removeAll()
        progress = ScanProgress()
        version &+= 1
    }

    func update(_ ip: IPv4, _ body: (inout HostInfo) -> Void) {
        lock.lock(); defer { lock.unlock() }
        var h = hosts[ip.raw] ?? HostInfo(ip: ip)
        body(&h)
        hosts[ip.raw] = h
        version &+= 1
    }

    func host(_ ip: IPv4) -> HostInfo? {
        lock.lock(); defer { lock.unlock() }
        return hosts[ip.raw]
    }

    func aliveIPs(in set: Set<UInt32>) -> [IPv4] {
        lock.lock(); defer { lock.unlock() }
        return hosts.values.filter { $0.isAlive && set.contains($0.ip.raw) }.map(\.ip).sorted()
    }

    func setPhase(_ phase: String, total: Int) {
        lock.lock(); defer { lock.unlock() }
        progress = ScanProgress(phase: phase, done: 0, total: total)
        version &+= 1
    }

    func advance(_ n: Int = 1) {
        lock.lock(); defer { lock.unlock() }
        progress.done += n
        version &+= 1
    }

    func reapplyVendors() {
        lock.lock(); defer { lock.unlock() }
        for (k, h) in hosts {
            guard let mac = h.mac else { continue }
            hosts[k]?.vendor = OUIDatabase.shared.vendor(for: mac)
        }
        version &+= 1
    }

    func snapshot(since v: Int) -> (version: Int, hosts: [HostInfo], progress: ScanProgress)? {
        lock.lock(); defer { lock.unlock() }
        guard version != v else { return nil }
        let alive = hosts.values.filter(\.isAlive).sorted { $0.ip < $1.ip }
        return (version, alive, progress)
    }
}
