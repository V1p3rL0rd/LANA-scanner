import Darwin
import Foundation

struct NetBIOSInfo: Equatable {
    var name: String?
    var group: String?
    var mac: String?
}

enum NameResolver {
    // MARK: Reverse DNS (system resolver)

    static func reverseDNS(_ ip: IPv4) -> String? {
        let addr = Sock.address(ip, port: 0)
        var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
        let hostLen = socklen_t(host.count)
        let rc = Sock.withSockaddr(addr) { sa, len in
            getnameinfo(sa, len, &host, hostLen, nil, 0, NI_NAMEREQD)
        }
        guard rc == 0 else { return nil }
        let name = String(cString: host).trimmingCharacters(in: CharacterSet(charactersIn: "."))
        return name.isEmpty || name == ip.description ? nil : name
    }

    // MARK: mDNS (unicast "legacy" query to host:5353 — answered by Apple devices, Avahi, printers…)

    static func mdnsName(_ ip: IPv4, timeout: Double) -> String? {
        let id = UInt16.random(in: 1...0xFFFE)
        var q: [UInt8] = [UInt8(id >> 8), UInt8(id & 0xFF), 0, 0, 0, 1, 0, 0, 0, 0, 0, 0]
        q += DNSMessage.encodeName(ip.reversePointerName)
        q += [0x00, 0x0C, 0x00, 0x01]  // QTYPE=PTR, QCLASS=IN
        guard let resp = UDPQuery.exchange(q, ip: ip, port: 5353, timeout: timeout) else { return nil }
        return DNSMessage.firstPTR(resp)
    }

    // MARK: NetBIOS node status (NBSTAT, UDP/137) — Windows, Samba, NAS

    static func netbios(_ ip: IPv4, timeout: Double) -> NetBIOSInfo? {
        let tid = UInt16.random(in: 1...0xFFFE)
        var q: [UInt8] = [UInt8(tid >> 8), UInt8(tid & 0xFF), 0x00, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]
        // Wildcard name "*" padded with NULs, first-level encoded (RFC 1002 §4.1).
        q.append(0x20)
        q += Array("CK".utf8)
        q += Array(repeating: UInt8(ascii: "A"), count: 30)
        q.append(0x00)
        q += [0x00, 0x21, 0x00, 0x01]  // NBSTAT, IN
        guard let resp = UDPQuery.exchange(q, ip: ip, port: 137, timeout: timeout) else { return nil }
        return parseNetBIOS(resp)
    }

    static func parseNetBIOS(_ m: [UInt8]) -> NetBIOSInfo? {
        guard m.count > 12 else { return nil }
        var off = 12
        if m[off] & 0xC0 == 0xC0 {
            off += 2
        } else {
            while off < m.count && m[off] != 0 { off += Int(m[off]) + 1 }
            off += 1
        }
        off += 10  // TYPE(2) CLASS(2) TTL(4) RDLENGTH(2)
        guard off < m.count else { return nil }
        let count = Int(m[off])
        off += 1
        guard count > 0, off + count * 18 <= m.count else { return nil }

        var info = NetBIOSInfo()
        let trimSet = CharacterSet.whitespaces.union(CharacterSet(charactersIn: "\0"))
        for i in 0..<count {
            let e = off + i * 18
            let name = (String(bytes: m[e..<(e + 15)], encoding: .isoLatin1) ?? "")
                .trimmingCharacters(in: trimSet)
            guard !name.isEmpty else { continue }
            let suffix = m[e + 15]
            let flags = UInt16(m[e + 16]) << 8 | UInt16(m[e + 17])
            let isGroup = flags & 0x8000 != 0
            if suffix == 0x00 {
                if isGroup { info.group = info.group ?? name } else { info.name = info.name ?? name }
            } else if suffix == 0x20, !isGroup, info.name == nil {
                info.name = name
            }
        }
        let macOff = off + count * 18
        if macOff + 6 <= m.count {
            let b = Array(m[macOff..<(macOff + 6)])
            if b.contains(where: { $0 != 0 }) { info.mac = MAC.normalize(MAC.format(b)) }
        }
        return (info.name == nil && info.group == nil) ? nil : info
    }
}

enum UDPQuery {
    /// Single request/response over UDP; only accepts a reply from `ip`.
    static func exchange(_ payload: [UInt8], ip: IPv4, port: UInt16, timeout: Double) -> [UInt8]? {
        let fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
        guard fd >= 0 else { return nil }
        defer { close(fd) }
        Sock.setReceiveTimeout(fd, seconds: 0.25)
        guard Sock.sendTo(fd, payload, ip, port: port) else { return nil }
        let deadline = Sock.nowNs() + UInt64(timeout * 1e9)
        while Sock.nowNs() < deadline {
            if let r = Sock.receive(fd, maxLen: 4096), r.from == ip { return r.bytes }
        }
        return nil
    }
}

enum DNSMessage {
    static func encodeName(_ name: String) -> [UInt8] {
        var out: [UInt8] = []
        for label in name.split(separator: ".") {
            let bytes = Array(label.utf8.prefix(63))
            out.append(UInt8(bytes.count))
            out += bytes
        }
        out.append(0)
        return out
    }

    /// Reads a (possibly compressed) name. Returns the name and the offset right after it.
    static func readName(_ m: [UInt8], _ start: Int) -> (String, Int)? {
        var labels: [String] = []
        var i = start
        var end = start
        var jumped = false
        var hops = 0
        while i < m.count {
            let len = Int(m[i])
            if len == 0 {
                if !jumped { end = i + 1 }
                return (labels.joined(separator: "."), end)
            }
            if len & 0xC0 == 0xC0 {
                guard i + 1 < m.count else { return nil }
                if !jumped { end = i + 2 }
                jumped = true
                i = ((len & 0x3F) << 8) | Int(m[i + 1])
                hops += 1
                if hops > 32 { return nil }  // pointer loop
                continue
            }
            guard i + 1 + len <= m.count else { return nil }
            labels.append(String(decoding: m[(i + 1)..<(i + 1 + len)], as: UTF8.self))
            i += 1 + len
        }
        return nil
    }

    static func firstPTR(_ m: [UInt8]) -> String? {
        guard m.count >= 12 else { return nil }
        func u16(_ o: Int) -> Int { Int(m[o]) << 8 | Int(m[o + 1]) }
        let qd = u16(4)
        let an = u16(6)
        var off = 12
        for _ in 0..<qd {
            guard let q = readName(m, off) else { return nil }
            off = q.1 + 4
        }
        for _ in 0..<an {
            guard let rr = readName(m, off), rr.1 + 10 <= m.count else { return nil }
            let next = rr.1
            let type = u16(next)
            let rdlen = u16(next + 8)
            let rdata = next + 10
            guard rdata + rdlen <= m.count else { return nil }
            if type == 12, let ptr = readName(m, rdata), !ptr.0.isEmpty { return ptr.0 }
            off = rdata + rdlen
        }
        return nil
    }
}
