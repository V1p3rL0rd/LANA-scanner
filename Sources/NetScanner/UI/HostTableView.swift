import SwiftUI

struct HostTableView: View {
    let hosts: [HostInfo]
    @Binding var selection: HostInfo.ID?
    @Binding var sortOrder: [KeyPathComparator<HostInfo>]
    @ObservedObject var vm: ScanViewModel

    var body: some View {
        Table(hosts, selection: $selection, sortOrder: $sortOrder) {
            TableColumn("", value: \HostInfo.statusRank) { h in
                StatusIcon(host: h)
            }
            .width(24)

            TableColumn("Name", value: \HostInfo.displayName) { h in
                Text(h.displayName.isEmpty ? "—" : h.displayName)
                    .foregroundColor(h.displayName.isEmpty ? .secondary : .primary)
            }
            .width(min: 120, ideal: 200)

            TableColumn("IP", value: \HostInfo.ip) { h in
                Text(h.ip.description).font(.system(.body, design: .monospaced))
            }
            .width(min: 110, ideal: 125)

            TableColumn("Vendor", value: \HostInfo.vendorSort) { h in
                Text(h.vendor ?? "").lineLimit(1)
            }
            .width(min: 100, ideal: 180)

            TableColumn("MAC", value: \HostInfo.macSort) { h in
                Text(h.mac ?? "").font(.system(.body, design: .monospaced))
            }
            .width(min: 130, ideal: 145)

            TableColumn("Open Ports", value: \HostInfo.openPortCount) { h in
                Text(h.portsSummary).lineLimit(1).help(h.portsSummary)
            }
            .width(min: 90, ideal: 160)

            TableColumn("Latency", value: \HostInfo.rttSort) { h in
                Text(h.rttText).monospacedDigit().foregroundStyle(.secondary)
            }
            .width(min: 50, ideal: 60)
        }
        .contextMenu(forSelectionType: HostInfo.ID.self) { ids in
            if let id = ids.first, let host = vm.host(id) {
                HostActionsMenu(host: host, vm: vm)
            }
        } primaryAction: { ids in
            // Double-click: open the first web UI, otherwise ping.
            guard let id = ids.first, let host = vm.host(id) else { return }
            if let link = HostLinks.links(for: host).first(where: { $0.id.hasPrefix("http") }) {
                vm.open(link.url)
            } else {
                vm.ping(host)
            }
        }
    }
}

struct StatusIcon: View {
    let host: HostInfo

    var body: some View {
        Image(systemName: host.symbolName)
            .font(host.isLocalMachine || host.isGateway ? .body : .system(size: 8))
            .foregroundStyle(color)
            .help(help)
    }

    private var color: Color {
        if host.isLocalMachine { return .accentColor }
        if host.isGateway { return .orange }
        return host.onlyARP ? .yellow : .green
    }

    private var help: String {
        if host.isLocalMachine { return String(localized: "This Mac") }
        if host.isGateway { return String(localized: "Default gateway") }
        if host.onlyARP { return String(localized: "Answers ARP only: firewalled host or a stale ARP cache entry") }
        return String(localized: "Online (\(host.methods.map(\.title).sorted().joined(separator: ", ")))")
    }
}
