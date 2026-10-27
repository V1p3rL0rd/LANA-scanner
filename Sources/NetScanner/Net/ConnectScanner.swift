import Darwin
import Foundation

struct ProbeTarget: Hashable, Sendable {
    let ip: IPv4
    let port: UInt16
}

enum ProbeOutcome {
    case open(Double)    // handshake completed, RTT ms
    case closed(Double)  // RST received — port closed, but the HOST IS ALIVE
    case filtered        // timeout / unreachable
}

/// Unprivileged TCP connect() scanner (nmap -sT equivalent).
/// One thread multiplexes up to `maxParallel` non-blocking sockets with poll(2),
/// so thousands of probes run concurrently without thread-per-connection overhead.
enum ConnectScanner {
    static func run(
        _ targets: [ProbeTarget],
        timeout: Double,
        maxParallel: Int,
        cancel: CancelFlag,
        onResult: (ProbeTarget, ProbeOutcome) -> Void
    ) {
        struct Pending {
            let fd: Int32
            let target: ProbeTarget
            let start: UInt64
        }

        let timeoutNs = UInt64(max(0.05, timeout) * 1e9)
        var limit = max(1, maxParallel)
        var pending: [Pending] = []
        pending.reserveCapacity(limit)
        var idx = 0

        while idx < targets.count || !pending.isEmpty {
            if cancel.isSet {
                for p in pending { _ = close(p.fd) }
                return
            }

            // 1. Fill the window with new non-blocking connects.
            while pending.count < limit && idx < targets.count {
                let t = targets[idx]
                let fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)
                if fd < 0 {
                    // EMFILE/ENOBUFS: shrink the window to what the system allows.
                    if pending.isEmpty {
                        onResult(t, .filtered)
                        idx += 1
                        continue
                    }
                    limit = max(16, pending.count)
                    break
                }
                idx += 1
                Sock.setNonBlocking(fd)
                Sock.setOption(fd, SOL_SOCKET, SO_NOSIGPIPE, 1)
                Sock.setAbortiveClose(fd)

                let start = Sock.nowNs()
                let addr = Sock.address(t.ip, port: t.port)
                let rc = Sock.withSockaddr(addr) { Darwin.connect(fd, $0, $1) }
                let err: Int32 = rc == 0 ? 0 : errno
                switch err {
                case 0:
                    onResult(t, .open(Double(Sock.nowNs() &- start) / 1e6))
                    close(fd)
                case EINPROGRESS:
                    pending.append(Pending(fd: fd, target: t, start: start))
                case ECONNREFUSED:
                    onResult(t, .closed(Double(Sock.nowNs() &- start) / 1e6))
                    close(fd)
                default:
                    onResult(t, .filtered)
                    close(fd)
                }
            }
            guard !pending.isEmpty else { continue }

            // 2. Wait for writability (= connect finished, successfully or not).
            var fds = pending.map { pollfd(fd: $0.fd, events: Int16(POLLOUT), revents: 0) }
            _ = poll(&fds, nfds_t(fds.count), 20)

            // 3. Harvest.
            let now = Sock.nowNs()
            var still: [Pending] = []
            still.reserveCapacity(pending.count)
            for (i, p) in pending.enumerated() {
                if fds[i].revents != 0 {
                    let e = Sock.socketError(p.fd)
                    let rtt = Double(now &- p.start) / 1e6
                    if e == 0 {
                        onResult(p.target, .open(rtt))
                    } else if e == ECONNREFUSED {
                        onResult(p.target, .closed(rtt))
                    } else {
                        onResult(p.target, .filtered)
                    }
                    close(p.fd)
                } else if now &- p.start > timeoutNs {
                    onResult(p.target, .filtered)
                    close(p.fd)
                } else {
                    still.append(p)
                }
            }
            pending = still
        }
    }
}
