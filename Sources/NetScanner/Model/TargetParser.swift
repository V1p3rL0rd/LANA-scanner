import Foundation

enum InputError: LocalizedError, Equatable {
    case empty
    case invalidTarget(String)
    case tooManyHosts(Int)
    case invalidPorts(String)

    var errorDescription: String? {
        switch self {
        case .empty:
            return String(localized: "Enter an address range, e.g. 192.168.1.0/24")
        case .invalidTarget(let t):
            return String(localized: "Cannot parse address or range: “\(t)”")
        case .tooManyHosts(let n):
            return String(localized: "Range too large (\(n) addresses). Maximum is \(TargetParser.maxHosts).")
        case .invalidPorts(let t):
            return String(localized: "Invalid port list: “\(t)”. Example: 22,80,443,8000-8100")
        }
    }
}

/// Parses nmap-like target specs:
///   192.168.1.0/24 · 10.0.0.1-10.0.0.50 · 10.0.0.1-50 · 172.16.0.5
/// separated by commas, semicolons or whitespace. Order is preserved, duplicates dropped.
enum TargetParser {
    static let maxHosts = 65_536

    static func parse(_ input: String) throws -> [IPv4] {
        let tokens = input
            .split(whereSeparator: { $0 == "," || $0 == ";" || $0.isWhitespace })
            .map(String.init)
        guard !tokens.isEmpty else { throw InputError.empty }

        var seen = Set<UInt32>()
        var result: [IPv4] = []

        func add(_ lo: UInt32, _ hi: UInt32, token: String) throws {
            guard hi >= lo else { throw InputError.invalidTarget(token) }
            let count = Int(hi - lo) + 1
            guard result.count + count <= maxHosts else {
                throw InputError.tooManyHosts(result.count + count)
            }
            for v in lo...hi where seen.insert(v).inserted {
                result.append(IPv4(raw: v))
            }
        }

        for token in tokens {
            if let slash = token.firstIndex(of: "/") {
                guard let ip = IPv4(String(token[..<slash])),
                      let prefixLength = Int(token[token.index(after: slash)...]),
                      (0...32).contains(prefixLength)
                else { throw InputError.invalidTarget(token) }
                let mask = IPv4.mask(prefix: prefixLength)
                let network = ip.raw & mask
                let broadcast = network | ~mask
                if prefixLength >= 31 {
                    try add(network, broadcast, token: token)          // /31, /32: no network/broadcast
                } else {
                    try add(network + 1, broadcast - 1, token: token)  // skip network & broadcast
                }
            } else if let dash = token.firstIndex(of: "-") {
                let left = String(token[..<dash])
                let right = String(token[token.index(after: dash)...])
                guard let start = IPv4(left) else { throw InputError.invalidTarget(token) }
                if let end = IPv4(right) {
                    try add(start.raw, end.raw, token: token)
                } else if let last = UInt8(right) {
                    try add(start.raw, (start.raw & 0xFFFF_FF00) | UInt32(last), token: token)
                } else {
                    throw InputError.invalidTarget(token)
                }
            } else {
                guard let ip = IPv4(token) else { throw InputError.invalidTarget(token) }
                try add(ip.raw, ip.raw, token: token)
            }
        }
        return result
    }
}

/// Parses "22,80,443,8000-8100" into a sorted unique port list.
enum PortSpec {
    static func parse(_ spec: String) throws -> [UInt16] {
        var set = Set<UInt16>()
        for token in spec.split(whereSeparator: { $0 == "," || $0.isWhitespace }) {
            let parts = token.split(separator: "-", omittingEmptySubsequences: false)
            if parts.count == 1, let p = UInt16(parts[0]), p > 0 {
                set.insert(p)
            } else if parts.count == 2, let a = UInt16(parts[0]), let b = UInt16(parts[1]), a > 0, a <= b {
                for p in a...b { set.insert(p) }
            } else {
                throw InputError.invalidPorts(String(token))
            }
        }
        guard !set.isEmpty else { throw InputError.invalidPorts(spec) }
        return set.sorted()
    }
}

enum ServiceDB {
    private static let overrides: [UInt16: String] = [
        445: "smb",
        3389: "rdp",
        5353: "mdns",
        62078: "iphone-sync",
    ]

    static let names: [UInt16: String] = {
        var d: [UInt16: String] = [:]
        for pair in PortData.serviceNames.split(separator: ",") {
            let kv = pair.split(separator: ":", maxSplits: 1)
            if kv.count == 2, let p = UInt16(kv[0]) { d[p] = String(kv[1]) }
        }
        for (k, v) in overrides { d[k] = v }
        return d
    }()

    static func name(for port: UInt16) -> String { names[port] ?? "unknown" }
}
