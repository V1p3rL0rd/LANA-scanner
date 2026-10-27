import Foundation

enum PortPreset: String, CaseIterable, Identifiable, Codable {
    case none, top100, top1000, wellKnown, all, custom

    var id: String { rawValue }

    var title: String {
        switch self {
        case .none: return String(localized: "No ports")
        case .top100: return "Top 100"
        case .top1000: return "Top 1000"
        case .wellKnown: return "1–1024"
        case .all: return String(localized: "All 1–65535")
        case .custom: return String(localized: "Custom list")
        }
    }
}

struct ScanSettings: Codable, Equatable {
    var portPreset: PortPreset = .top100
    var customPorts = "21-23,25,53,80,110,139,143,443,445,3306,3389,5432,5900,8080,8443"
    var timeoutMs = 800
    var maxParallel = 512
    var resolveNames = true
    var grabBanners = true

    private static let defaultsKey = "scanSettings.v1"

    func ports() throws -> [UInt16] {
        switch portPreset {
        case .none: return []
        case .top100: return try PortSpec.parse(PortData.top100)
        case .top1000: return try PortSpec.parse(PortData.top1000)
        case .wellKnown: return Array(1...1024)
        case .all: return Array(1...UInt16.max)
        case .custom: return try PortSpec.parse(customPorts)
        }
    }

    static func load() -> ScanSettings {
        guard let data = UserDefaults.standard.data(forKey: defaultsKey),
              let s = try? JSONDecoder().decode(ScanSettings.self, from: data)
        else { return ScanSettings() }
        return s
    }

    func save() {
        if let data = try? JSONEncoder().encode(self) {
            UserDefaults.standard.set(data, forKey: Self.defaultsKey)
        }
    }
}
