import Darwin
import Foundation

struct NetInterface: Identifiable, Hashable, Sendable {
    let name: String
    let address: IPv4
    let prefixLength: Int
    var mac: String?

    var id: String { "\(name)-\(address)" }
    var network: IPv4 { IPv4(raw: address.raw & IPv4.mask(prefix: prefixLength)) }
    var broadcast: IPv4 { IPv4(raw: network.raw | ~IPv4.mask(prefix: prefixLength)) }
    var cidr: String { "\(network)/\(prefixLength)" }
    var label: String { "\(name) — \(address) (\(cidr))" }

    func contains(_ ip: IPv4) -> Bool { ip.raw & IPv4.mask(prefix: prefixLength) == network.raw }

    /// Whole subnet up to /22 (1022 hosts); for larger subnets suggest the /24 around our address.
    var suggestedRange: String {
        prefixLength >= 22 ? cidr : "\(IPv4(raw: address.raw & 0xFFFF_FF00))/24"
    }
}

enum Interfaces {
    /// Up, running, non-loopback IPv4 interfaces with their link-layer (MAC) address.
    static func list() -> [NetInterface] {
        var ifap: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&ifap) == 0, let first = ifap else { return [] }
        defer { freeifaddrs(ifap) }

        var macs: [String: String] = [:]
        var result: [NetInterface] = []

        for ptr in sequence(first: first, next: { $0.pointee.ifa_next }) {
            let entry = ptr.pointee
            guard let sa = entry.ifa_addr else { continue }
            let name = String(cString: entry.ifa_name)
            let flags = Int32(truncatingIfNeeded: entry.ifa_flags)

            switch Int32(sa.pointee.sa_family) {
            case AF_LINK:
                if let mac = linkAddress(sa) { macs[name] = mac }
            case AF_INET:
                guard flags & IFF_UP != 0, flags & IFF_RUNNING != 0, flags & IFF_LOOPBACK == 0,
                      let maskPtr = entry.ifa_netmask
                else { continue }
                let ip = sa.withMemoryRebound(to: sockaddr_in.self, capacity: 1) {
                    IPv4(raw: UInt32(bigEndian: $0.pointee.sin_addr.s_addr))
                }
                let mask = maskPtr.withMemoryRebound(to: sockaddr_in.self, capacity: 1) {
                    UInt32(bigEndian: $0.pointee.sin_addr.s_addr)
                }
                result.append(NetInterface(name: name, address: ip, prefixLength: mask.nonzeroBitCount))
            default:
                continue
            }
        }
        for i in result.indices { result[i].mac = macs[result[i].name] }
        // Physical en* first, link-local (169.254/16) last.
        return result.sorted { a, b in
            func rank(_ i: NetInterface) -> Int {
                if i.address.raw >> 16 == 0xA9FE { return 2 }
                return i.name.hasPrefix("en") ? 0 : 1
            }
            return (rank(a), a.name) < (rank(b), b.name)
        }
    }

    private static func linkAddress(_ sa: UnsafeMutablePointer<sockaddr>) -> String? {
        sa.withMemoryRebound(to: sockaddr_dl.self, capacity: 1) { dl -> String? in
            let nameLen = Int(dl.pointee.sdl_nlen)
            guard dl.pointee.sdl_alen == 6 else { return nil }
            let dataOffset = MemoryLayout<sockaddr_dl>.offset(of: \sockaddr_dl.sdl_data) ?? 8
            let base = UnsafeRawPointer(dl).advanced(by: dataOffset + nameLen)
            let bytes = (0..<6).map { base.load(fromByteOffset: $0, as: UInt8.self) }
            return MAC.normalize(MAC.format(bytes))
        }
    }

    /// Default gateway and its interface, via `route -n get default`.
    static func defaultRoute() -> (gateway: IPv4?, interface: String?) {
        guard let out = Shell.run("/sbin/route", ["-n", "get", "default"]) else { return (nil, nil) }
        var gateway: IPv4?
        var iface: String?
        for line in out.split(separator: "\n") {
            let t = line.trimmingCharacters(in: .whitespaces)
            if t.hasPrefix("gateway:") {
                gateway = IPv4(String(t.dropFirst("gateway:".count)))
            } else if t.hasPrefix("interface:") {
                iface = String(t.dropFirst("interface:".count)).trimmingCharacters(in: .whitespaces)
            }
        }
        return (gateway, iface)
    }
}
