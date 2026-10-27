import Darwin
import Foundation

/// Lightweight service/version detection (a tiny subset of nmap -sV):
/// 1) wait for a greeting (SSH, FTP, SMTP, POP3, IMAP, VNC, MySQL…);
/// 2) if silent, send an HTTP HEAD probe and parse the Server header.
enum ServiceProbe {
    struct Result: Equatable {
        var service: String?
        var banner: String?
    }

    /// TLS-wrapped ports: a plaintext probe is pointless and would only produce noise.
    static let tlsPorts: Set<UInt16> = [443, 465, 636, 853, 989, 990, 992, 993, 994, 995, 5061, 5986, 8443, 9443]

    static func probe(_ ip: IPv4, port: UInt16, timeout: Double) -> Result {
        if tlsPorts.contains(port) { return Result(service: nil, banner: "TLS") }
        guard let fd = openConnection(ip, port, timeout) else { return Result() }
        defer { close(fd) }

        var data = readSome(fd, waitMs: 1500)
        if data.isEmpty {
            let req = "HEAD / HTTP/1.0\r\nHost: \(ip)\r\nUser-Agent: LANAScanner\r\nConnection: close\r\n\r\n"
            let bytes = Array(req.utf8)
            _ = bytes.withUnsafeBytes { send(fd, $0.baseAddress, $0.count, 0) }
            data = readSome(fd, waitMs: 1500)
        }
        return classify(data, port: port)
    }

    private static func openConnection(_ ip: IPv4, _ port: UInt16, _ timeout: Double) -> Int32? {
        let fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)
        guard fd >= 0 else { return nil }
        Sock.setNonBlocking(fd)
        Sock.setOption(fd, SOL_SOCKET, SO_NOSIGPIPE, 1)
        let addr = Sock.address(ip, port: port)
        let rc = Sock.withSockaddr(addr) { Darwin.connect(fd, $0, $1) }
        if rc != 0 {
            guard errno == EINPROGRESS else { close(fd); return nil }
            var pfd = pollfd(fd: fd, events: Int16(POLLOUT), revents: 0)
            guard poll(&pfd, 1, Int32(timeout * 1000)) == 1, Sock.socketError(fd) == 0 else {
                close(fd)
                return nil
            }
        }
        return fd
    }

    private static func readSome(_ fd: Int32, waitMs: Int32) -> [UInt8] {
        var pfd = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
        guard poll(&pfd, 1, waitMs) == 1 else { return [] }
        var buf = [UInt8](repeating: 0, count: 2048)
        let n = buf.withUnsafeMutableBytes { recv(fd, $0.baseAddress, $0.count, 0) }
        return n > 0 ? Array(buf[0..<n]) : []
    }

    static func classify(_ data: [UInt8], port: UInt16) -> Result {
        guard !data.isEmpty else { return Result() }

        // MySQL/MariaDB handshake: 3-byte length, seq=0, protocol=10, NUL-terminated version.
        if data.count > 6, data[3] == 0, data[4] == 0x0A, let end = data[5...].firstIndex(of: 0), end > 5 {
            let version = String(decoding: data[5..<end], as: UTF8.self)
            if version.first?.isNumber == true {
                return Result(service: version.lowercased().contains("mariadb") ? "mariadb" : "mysql",
                              banner: "MySQL \(version)")
            }
        }

        let text = String(decoding: data, as: UTF8.self)
        let firstLine = sanitize(text.components(separatedBy: "\n").first ?? "")

        if text.hasPrefix("HTTP/") {
            let server = text.components(separatedBy: "\r\n")
                .first { $0.lowercased().hasPrefix("server:") }
                .map { sanitize(String($0.dropFirst("server:".count))) }
            let banner = [server, firstLine].compactMap { $0 }.filter { !$0.isEmpty }.joined(separator: " · ")
            return Result(service: "http", banner: banner)
        }
        if text.hasPrefix("SSH-") { return Result(service: "ssh", banner: firstLine) }
        if text.hasPrefix("RFB ") { return Result(service: "vnc", banner: firstLine) }
        if text.hasPrefix("220") {
            let svc = (port == 21 || text.lowercased().contains("ftp")) ? "ftp" : "smtp"
            return Result(service: svc, banner: firstLine)
        }
        if text.hasPrefix("+OK") { return Result(service: "pop3", banner: firstLine) }
        if text.hasPrefix("* OK") { return Result(service: "imap", banner: firstLine) }

        let sample = data.prefix(64)
        let printable = sample.filter { (0x20...0x7E).contains($0) || $0 == 0x09 || $0 == 0x0A || $0 == 0x0D }.count
        if printable * 10 >= sample.count * 8, !firstLine.isEmpty {
            return Result(service: nil, banner: firstLine)
        }
        return Result(service: nil, banner: String(localized: "\(data.count) bytes of binary data"))
    }

    static func sanitize(_ s: String) -> String {
        let chars = s.unicodeScalars.map { sc -> Character in
            (0x20...0x7E).contains(sc.value) || sc.value > 0x9F ? Character(sc) : " "
        }
        return String(String(chars).trimmingCharacters(in: .whitespacesAndNewlines).prefix(160))
    }
}

enum WakeOnLAN {
    /// Magic packet: 6×0xFF + 16×MAC, to UDP 9 and 7 on limited + directed broadcast.
    static func send(mac: String, broadcasts: [IPv4]) -> Bool {
        guard let m = MAC.bytes(mac) else { return false }
        var pkt = [UInt8](repeating: 0xFF, count: 6)
        for _ in 0..<16 { pkt += m }

        let fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
        guard fd >= 0 else { return false }
        defer { close(fd) }
        Sock.setOption(fd, SOL_SOCKET, SO_BROADCAST, 1)

        var ok = false
        let ports: [UInt16] = [9, 7]
        for dest in Set(broadcasts + [IPv4(raw: 0xFFFF_FFFF)]) {
            for port in ports {
                if Sock.sendTo(fd, pkt, dest, port: port) { ok = true }
            }
        }
        return ok
    }
}
