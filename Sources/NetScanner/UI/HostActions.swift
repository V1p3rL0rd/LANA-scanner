import SwiftUI

struct ServiceLink: Identifiable, Hashable {
    let id: String
    let title: String
    let icon: String
    let url: URL
}

enum HostLinks {
    /// "Open with…" links derived from the host's open ports.
    static func links(for host: HostInfo) -> [ServiceLink] {
        var out: [ServiceLink] = []
        let ip = host.ip.description

        func add(_ id: String, _ title: String, _ icon: String, _ url: String) {
            guard !out.contains(where: { $0.id == id }), let u = URL(string: url) else { return }
            out.append(ServiceLink(id: id, title: title, icon: icon, url: u))
        }

        for p in host.openPorts {
            let svc = p.service.lowercased()
            switch p.port {
            case 22: add("ssh", "SSH", "terminal", "ssh://\(ip)")
            case 21: add("ftp", "FTP", "tray.and.arrow.down", "ftp://\(ip)")
            case 139, 445: add("smb", "SMB (Finder)", "folder", "smb://\(ip)")
            case 3389: add("rdp", "RDP", "desktopcomputer", "rdp://full%20address=s:\(ip):3389")
            case 5900: add("vnc", "VNC / Screen Sharing", "display", "vnc://\(ip)")
            default:
                let isTLS = svc.contains("https") || p.port == 443 || p.port == 8443 || (p.banner == "TLS" && svc.contains("http"))
                if isTLS {
                    let url = p.port == 443 ? "https://\(ip)" : "https://\(ip):\(p.port)"
                    add("https-\(p.port)", "HTTPS :\(p.port)", "lock", url)
                } else if svc.contains("http") {
                    let url = p.port == 80 ? "http://\(ip)" : "http://\(ip):\(p.port)"
                    add("http-\(p.port)", "HTTP :\(p.port)", "globe", url)
                }
            }
        }
        return out
    }
}

/// Shared by the table's context menu and the detail pane.
struct HostActionsMenu: View {
    let host: HostInfo
    @ObservedObject var vm: ScanViewModel

    var body: some View {
        let links = HostLinks.links(for: host)
        ForEach(links) { link in
            Button { vm.open(link.url) } label: { Label(link.title, systemImage: link.icon) }
        }
        if !links.isEmpty { Divider() }

        Button { vm.ping(host) } label: { Label("Ping", systemImage: "waveform.path.ecg") }
        Button { vm.traceroute(host) } label: {
            Label("Traceroute", systemImage: "point.topleft.down.curvedto.point.bottomright.up")
        }
        Button { vm.rescanPorts(host) } label: { Label("Rescan Ports", systemImage: "arrow.clockwise") }
            .disabled(vm.isScanning)
        if host.mac != nil && !host.isLocalMachine {
            Button { vm.wake(host) } label: { Label("Wake-on-LAN", systemImage: "bolt") }
        }
        Divider()
        Button { vm.copy(host.ip.description) } label: { Label("Copy IP", systemImage: "doc.on.doc") }
        if let mac = host.mac {
            Button { vm.copy(mac) } label: { Label("Copy MAC", systemImage: "doc.on.doc") }
        }
        if !host.displayName.isEmpty {
            Button { vm.copy(host.displayName) } label: { Label("Copy Name", systemImage: "doc.on.doc") }
        }
    }
}
