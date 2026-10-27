import Darwin
import Foundation

/// ICMP echo sweep WITHOUT root: macOS allows SOCK_DGRAM + IPPROTO_ICMP for unprivileged users
/// (the same mechanism Apple's SimplePing sample uses).
enum ICMPPinger {
    static func sweep(
        _ targets: [IPv4],
        timeout: Double,
        cancel: CancelFlag,
        onReply: (IPv4, Double) -> Void
    ) {
        guard !targets.isEmpty else { return }
        let fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP)
        guard fd >= 0 else { return }
        defer { close(fd) }
        Sock.setNonBlocking(fd)

        let ident = UInt16(truncatingIfNeeded: getpid())
        let wanted = Set(targets.map(\.raw))
        let timeoutNs = UInt64(timeout * 1e9)
        var sentAt: [UInt32: UInt64] = [:]
        var replied = Set<UInt32>()
        var idx = 0
        var lastSend = Sock.nowNs()

        while !cancel.isSet {
            // Send in small bursts to avoid overflowing the socket buffer / NIC queue.
            var burst = 0
            while idx < targets.count && burst < 16 {
                let ip = targets[idx]
                let pkt = packet(id: ident, seq: UInt16(truncatingIfNeeded: idx))
                _ = Sock.sendTo(fd, pkt, ip, port: 0)
                lastSend = Sock.nowNs()
                sentAt[ip.raw] = lastSend
                idx += 1
                burst += 1
            }

            var pfd = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
            _ = poll(&pfd, 1, idx < targets.count ? 2 : 50)

            while let r = Sock.receive(fd) {
                guard wanted.contains(r.from.raw), !replied.contains(r.from.raw), isEchoReply(r.bytes) else { continue }
                replied.insert(r.from.raw)
                let now = Sock.nowNs()
                let sent = sentAt[r.from.raw] ?? now
                onReply(r.from, Double(now &- sent) / 1e6)
            }

            if idx >= targets.count {
                if replied.count == wanted.count || Sock.nowNs() &- lastSend > timeoutNs { break }
            }
        }
    }

    static func packet(id: UInt16, seq: UInt16) -> [UInt8] {
        var p: [UInt8] = [8, 0, 0, 0, UInt8(id >> 8), UInt8(id & 0xFF), UInt8(seq >> 8), UInt8(seq & 0xFF)]
        p += Array("NetScanner-ping!".utf8)
        let c = checksum(p)
        p[2] = UInt8(c >> 8)
        p[3] = UInt8(c & 0xFF)
        return p
    }

    /// RFC 1071 Internet checksum.
    static func checksum(_ bytes: [UInt8]) -> UInt16 {
        var sum: UInt32 = 0
        var i = 0
        while i + 1 < bytes.count {
            sum += UInt32(bytes[i]) << 8 | UInt32(bytes[i + 1])
            i += 2
        }
        if i < bytes.count { sum += UInt32(bytes[i]) << 8 }
        while sum >> 16 != 0 { sum = (sum & 0xFFFF) + (sum >> 16) }
        return ~UInt16(sum)
    }

    /// The kernel may or may not prepend the IPv4 header on DGRAM ICMP sockets — handle both.
    static func isEchoReply(_ bytes: [UInt8]) -> Bool {
        var off = 0
        if let first = bytes.first, first >> 4 == 4 { off = Int(first & 0x0F) * 4 }
        guard bytes.count >= off + 8 else { return false }
        return bytes[off] == 0  // ICMP type 0 = echo reply
    }
}

enum ARPTable {
    /// Fire one UDP datagram at each local-subnet IP: the kernel must ARP-resolve the
    /// destination first, which fills the ARP cache even for hosts that drop ICMP/TCP.
    static func poke(_ targets: [IPv4]) {
        guard !targets.isEmpty else { return }
        let fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
        guard fd >= 0 else { return }
        defer { close(fd) }
        Sock.setNonBlocking(fd)
        for (i, ip) in targets.enumerated() {
            _ = Sock.sendTo(fd, [0], ip, port: 9)  // discard service
            if i % 64 == 63 { usleep(2_000) }
        }
    }

    /// Parses `arp -an`:  ? (192.168.1.1) at a4:2b:b0:1:2:3 on en0 ifscope [ethernet]
    static func read() -> [UInt32: String] {
        guard let out = Shell.run("/usr/sbin/arp", ["-an"]) else { return [:] }
        return parse(out)
    }

    static func parse(_ text: String) -> [UInt32: String] {
        var map: [UInt32: String] = [:]
        for line in text.split(separator: "\n") {
            let parts = line.split(separator: " ")
            guard parts.count >= 4, parts[2] == "at",
                  let ip = IPv4(parts[1].trimmingCharacters(in: CharacterSet(charactersIn: "()"))),
                  let mac = MAC.normalize(String(parts[3]))
            else { continue }
            map[ip.raw] = mac
        }
        return map
    }
}
