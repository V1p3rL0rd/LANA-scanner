import Darwin
import Foundation

/// IPv4 address stored in host byte order so ranges/masks are plain integer math.
struct IPv4: Hashable, Comparable, CustomStringConvertible, Sendable {
    let raw: UInt32

    init(raw: UInt32) { self.raw = raw }

    init?(_ string: String) {
        var addr = in_addr()
        let trimmed = string.trimmingCharacters(in: .whitespaces)
        let rc = trimmed.withCString { inet_pton(AF_INET, $0, &addr) }
        guard rc == 1 else { return nil }
        raw = UInt32(bigEndian: addr.s_addr)
    }

    var description: String {
        "\(raw >> 24).\((raw >> 16) & 0xFF).\((raw >> 8) & 0xFF).\(raw & 0xFF)"
    }

    /// "4.3.2.1.in-addr.arpa" for 1.2.3.4 — used by DNS/mDNS PTR queries.
    var reversePointerName: String {
        "\(raw & 0xFF).\((raw >> 8) & 0xFF).\((raw >> 16) & 0xFF).\(raw >> 24).in-addr.arpa"
    }

    static func < (lhs: IPv4, rhs: IPv4) -> Bool { lhs.raw < rhs.raw }

    static func mask(prefix bits: Int) -> UInt32 {
        guard bits > 0 else { return 0 }
        guard bits < 32 else { return .max }
        return UInt32.max << UInt32(32 - bits)
    }
}

enum MAC {
    /// "a4:2b:b0:1:2:3" (macOS `arp` style) -> "A4:2B:B0:01:02:03". Rejects broadcast/zero.
    static func normalize(_ s: String) -> String? {
        guard let b = bytes(s) else { return nil }
        let text = format(b)
        if text == "FF:FF:FF:FF:FF:FF" || text == "00:00:00:00:00:00" { return nil }
        return text
    }

    static func bytes(_ s: String) -> [UInt8]? {
        let comps = s.split(whereSeparator: { $0 == ":" || $0 == "-" })
        guard comps.count == 6 else { return nil }
        var out: [UInt8] = []
        for c in comps {
            guard c.count <= 2, let v = UInt8(c, radix: 16) else { return nil }
            out.append(v)
        }
        return out
    }

    static func format(_ b: [UInt8]) -> String {
        b.map { String(format: "%02X", $0) }.joined(separator: ":")
    }

    /// Locally-administered bit: iOS/Android/macOS "Private Wi-Fi address".
    static func isRandomized(_ s: String) -> Bool {
        guard let first = bytes(s)?.first else { return false }
        return first & 0x02 != 0
    }
}
