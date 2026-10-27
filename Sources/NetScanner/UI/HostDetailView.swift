import SwiftUI

struct HostDetailView: View {
    let host: HostInfo
    @ObservedObject var vm: ScanViewModel

    private var infoRows: [(String, String)] {
        var rows: [(String, String)] = []
        func add(_ k: String, _ v: String?) {
            if let v, !v.isEmpty { rows.append((k, v)) }
        }
        add("IP", host.ip.description)
        add("DNS", host.dnsName)
        add("mDNS", host.mdnsName)
        add("NetBIOS", host.netbiosName)
        add(String(localized: "Workgroup"), host.workgroup)
        add("MAC", host.mac)
        add(String(localized: "Vendor"), host.vendor)
        add(String(localized: "Latency"), host.rttText)
        add(String(localized: "Discovered via"), host.methods.map(\.title).sorted().joined(separator: ", "))
        return rows
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                header
                Grid(alignment: .leading, horizontalSpacing: 12, verticalSpacing: 6) {
                    ForEach(infoRows, id: \.0) { row in
                        GridRow {
                            Text(row.0).foregroundStyle(.secondary)
                            Text(row.1).textSelection(.enabled)
                        }
                    }
                }
                actions
                ports
            }
            .padding(16)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    private var header: some View {
        HStack(spacing: 12) {
            Image(systemName: host.isLocalMachine ? "laptopcomputer" : (host.isGateway ? "network" : "desktopcomputer"))
                .font(.system(size: 30))
                .foregroundStyle(Color.accentColor)
            VStack(alignment: .leading, spacing: 2) {
                Text(host.displayName.isEmpty ? host.ip.description : host.displayName)
                    .font(.title2.bold())
                    .textSelection(.enabled)
                HStack(spacing: 6) {
                    if host.isLocalMachine { Badge(text: String(localized: "This Mac"), color: .blue) }
                    if host.isGateway { Badge(text: String(localized: "Gateway"), color: .orange) }
                    if host.onlyARP { Badge(text: String(localized: "ARP only"), color: .yellow) }
                }
            }
        }
    }

    private var actions: some View {
        let links = HostLinks.links(for: host)
        return VStack(alignment: .leading, spacing: 8) {
            Text("Actions").font(.headline)
            LazyVGrid(columns: [GridItem(.adaptive(minimum: 140), alignment: .leading)], alignment: .leading, spacing: 6) {
                ForEach(links) { link in
                    Button { vm.open(link.url) } label: {
                        Label(link.title, systemImage: link.icon).frame(maxWidth: .infinity, alignment: .leading)
                    }
                }
                Button { vm.ping(host) } label: {
                    Label("Ping", systemImage: "waveform.path.ecg").frame(maxWidth: .infinity, alignment: .leading)
                }
                Button { vm.traceroute(host) } label: {
                    Label("Traceroute", systemImage: "point.topleft.down.curvedto.point.bottomright.up")
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
                if host.mac != nil && !host.isLocalMachine {
                    Button { vm.wake(host) } label: {
                        Label("Wake-on-LAN", systemImage: "bolt").frame(maxWidth: .infinity, alignment: .leading)
                    }
                }
                Button { vm.copy(host.ip.description) } label: {
                    Label("Copy IP", systemImage: "doc.on.doc").frame(maxWidth: .infinity, alignment: .leading)
                }
            }
        }
    }

    private var ports: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text("Open TCP Ports").font(.headline)
                Spacer()
                Button { vm.rescanPorts(host) } label: { Label("Rescan", systemImage: "arrow.clockwise") }
                    .disabled(vm.isScanning)
                    .controlSize(.small)
            }
            if host.openPorts.isEmpty {
                Text(LocalizedStringKey(host.portsScanned ? "No open ports found" : "Ports not scanned"))
                    .foregroundStyle(.secondary)
            } else {
                VStack(alignment: .leading, spacing: 0) {
                    ForEach(host.openPorts) { p in
                        HStack(alignment: .firstTextBaseline, spacing: 10) {
                            Text("\(String(p.port))/tcp")
                                .font(.system(.body, design: .monospaced))
                                .frame(width: 84, alignment: .leading)
                            Text(p.service)
                                .frame(width: 110, alignment: .leading)
                                .lineLimit(1)
                            Text(p.banner ?? "")
                                .foregroundStyle(.secondary)
                                .lineLimit(2)
                                .textSelection(.enabled)
                        }
                        .padding(.vertical, 4)
                        Divider()
                    }
                }
            }
        }
    }
}

struct Badge: View {
    let text: String
    let color: Color

    var body: some View {
        Text(text)
            .font(.caption.bold())
            .padding(.horizontal, 6)
            .padding(.vertical, 2)
            .background(color.opacity(0.2), in: Capsule())
            .foregroundStyle(color)
    }
}
