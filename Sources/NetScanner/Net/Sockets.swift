import Darwin
import Foundation

/// Thin, allocation-free helpers over BSD sockets.
enum Sock {
    static func address(_ ip: IPv4, port: UInt16) -> sockaddr_in {
        var a = sockaddr_in()
        a.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        a.sin_family = sa_family_t(AF_INET)
        a.sin_port = port.bigEndian
        a.sin_addr = in_addr(s_addr: ip.raw.bigEndian)
        return a
    }

    static func withSockaddr<T>(_ addr: sockaddr_in, _ body: (UnsafePointer<sockaddr>, socklen_t) -> T) -> T {
        var a = addr
        return withUnsafePointer(to: &a) { p in
            p.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                body($0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
    }

    static func setNonBlocking(_ fd: Int32) {
        let flags = fcntl(fd, F_GETFL, 0)
        _ = fcntl(fd, F_SETFL, flags | O_NONBLOCK)
    }

    static func setOption(_ fd: Int32, _ level: Int32, _ name: Int32, _ value: Int32) {
        var v = value
        _ = setsockopt(fd, level, name, &v, socklen_t(MemoryLayout<Int32>.size))
    }

    static func setReceiveTimeout(_ fd: Int32, seconds: Double) {
        var tv = timeval(tv_sec: Int(seconds), tv_usec: Int32((seconds - floor(seconds)) * 1_000_000))
        _ = setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
    }

    /// RST on close instead of FIN: no TIME_WAIT pile-up during large connect scans (same trick nmap uses).
    static func setAbortiveClose(_ fd: Int32) {
        var lg = linger(l_onoff: 1, l_linger: 0)
        _ = setsockopt(fd, SOL_SOCKET, SO_LINGER, &lg, socklen_t(MemoryLayout<linger>.size))
    }

    static func socketError(_ fd: Int32) -> Int32 {
        var err: Int32 = 0
        var len = socklen_t(MemoryLayout<Int32>.size)
        return getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len) == 0 ? err : errno
    }

    static func sendTo(_ fd: Int32, _ bytes: [UInt8], _ ip: IPv4, port: UInt16) -> Bool {
        let addr = address(ip, port: port)
        let sent = bytes.withUnsafeBytes { buf in
            withSockaddr(addr) { sendto(fd, buf.baseAddress, buf.count, 0, $0, $1) }
        }
        return sent == bytes.count
    }

    static func receive(_ fd: Int32, maxLen: Int = 2048) -> (bytes: [UInt8], from: IPv4)? {
        var buf = [UInt8](repeating: 0, count: maxLen)
        var from = sockaddr_in()
        var len = socklen_t(MemoryLayout<sockaddr_in>.size)
        let n = buf.withUnsafeMutableBytes { b -> Int in
            withUnsafeMutablePointer(to: &from) { p in
                p.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    recvfrom(fd, b.baseAddress, b.count, 0, $0, &len)
                }
            }
        }
        guard n > 0 else { return nil }
        return (Array(buf[0..<n]), IPv4(raw: UInt32(bigEndian: from.sin_addr.s_addr)))
    }

    static func nowNs() -> UInt64 { DispatchTime.now().uptimeNanoseconds }

    /// macOS default soft limit is 256 fds — far too low for a parallel connect scan.
    static func raiseFileDescriptorLimit(to desired: rlim_t = 10_240) {
        var rl = rlimit()
        guard getrlimit(RLIMIT_NOFILE, &rl) == 0 else { return }
        let target = min(desired, rl.rlim_max)
        if rl.rlim_cur < target {
            rl.rlim_cur = target
            _ = setrlimit(RLIMIT_NOFILE, &rl)
        }
    }

    static func currentFileLimit() -> Int {
        var rl = rlimit()
        guard getrlimit(RLIMIT_NOFILE, &rl) == 0 else { return 256 }
        return Int(min(rl.rlim_cur, 1_000_000))
    }
}

/// Thread-safe cancellation flag shared by all workers of a scan.
final class CancelFlag: @unchecked Sendable {
    private let lock = NSLock()
    private var value = false

    var isSet: Bool {
        lock.lock(); defer { lock.unlock() }
        return value
    }

    func set() {
        lock.lock(); value = true; lock.unlock()
    }
}

/// Bounded fan-out of blocking work onto a private concurrent GCD queue.
func parallelForEach<T>(_ items: [T], maxConcurrent: Int, cancel: CancelFlag, _ body: @escaping (T) -> Void) {
    let queue = DispatchQueue(label: "netscanner.pool", qos: .userInitiated, attributes: .concurrent)
    let slots = DispatchSemaphore(value: max(1, maxConcurrent))
    let group = DispatchGroup()
    for item in items {
        if cancel.isSet { break }
        slots.wait()
        queue.async(group: group) {
            defer { slots.signal() }
            if !cancel.isSet { body(item) }
        }
    }
    group.wait()
}

enum Shell {
    /// Runs a system binary synchronously and returns stdout (nil on launch failure).
    static func run(_ path: String, _ args: [String]) -> String? {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: path)
        p.arguments = args
        let pipe = Pipe()
        p.standardOutput = pipe
        p.standardError = FileHandle.nullDevice
        do { try p.run() } catch { return nil }
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        return String(data: data, encoding: .utf8)
    }
}
