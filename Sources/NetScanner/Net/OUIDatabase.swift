import Foundation

/// MAC prefix -> manufacturer. Loaded from ~/Library/Application Support/NetScanner/oui.txt
/// (downloaded from IEEE on first launch) or from the app bundle if present.
final class OUIDatabase: @unchecked Sendable {
    static let shared = OUIDatabase()

    private let lock = NSLock()
    private var map: [UInt32: String] = [:]
    private var loaded = false

    static let sources: [URL] = [
        URL(string: "https://standards-oui.ieee.org/oui/oui.csv")!,
        URL(string: "https://raw.githubusercontent.com/nmap/nmap/master/nmap-mac-prefixes")!,
    ]

    static var storeURL: URL {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        return base.appendingPathComponent("NetScanner", isDirectory: true).appendingPathComponent("oui.txt")
    }

    func loadedCount() -> Int {
        loadIfNeeded()
        lock.lock(); defer { lock.unlock() }
        return map.count
    }

    func vendor(for mac: String) -> String? {
        loadIfNeeded()
        guard let b = MAC.bytes(mac) else { return nil }
        let key = UInt32(b[0]) << 16 | UInt32(b[1]) << 8 | UInt32(b[2])
        lock.lock()
        let v = map[key]
        lock.unlock()
        if let v { return v }
        return b[0] & 0x02 != 0 ? "Случайный MAC (приватный адрес)" : nil
    }

    private func loadIfNeeded() {
        lock.lock(); defer { lock.unlock() }
        guard !loaded else { return }
        loaded = true
        let candidates = [Self.storeURL, Bundle.main.url(forResource: "oui", withExtension: "txt")].compactMap { $0 }
        for url in candidates {
            if let text = try? String(contentsOf: url, encoding: .utf8) {
                let parsed = Self.parse(text)
                if !parsed.isEmpty { map = parsed; return }
            }
        }
    }

    /// Downloads the registry, stores a normalized copy, swaps it in. Returns entry count.
    func update() async throws -> Int {
        var lastError: Error = URLError(.unknown)
        for url in Self.sources {
            do {
                var req = URLRequest(url: url, timeoutInterval: 60)
                // IEEE rejects requests without a browser-like User-Agent.
                req.setValue("Mozilla/5.0 (Macintosh; Intel Mac OS X) LANAScanner/1.0", forHTTPHeaderField: "User-Agent")
                let (data, resp) = try await URLSession.shared.data(for: req)
                guard (resp as? HTTPURLResponse)?.statusCode == 200 else { throw URLError(.badServerResponse) }
                let text = String(data: data, encoding: .utf8) ?? String(decoding: data, as: UTF8.self)
                let parsed = Self.parse(text)
                guard parsed.count > 10_000 else { throw URLError(.cannotParseResponse) }
                try save(parsed)
                install(parsed)
                return parsed.count
            } catch {
                lastError = error
            }
        }
        throw lastError
    }

    private func install(_ m: [UInt32: String]) {
        lock.lock(); defer { lock.unlock() }
        map = m
        loaded = true
    }

    private func save(_ m: [UInt32: String]) throws {
        let dir = Self.storeURL.deletingLastPathComponent()
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let body = m.keys.sorted()
            .map { String(format: "%06X\t", $0) + (m[$0] ?? "") }
            .joined(separator: "\n")
        try body.write(to: Self.storeURL, atomically: true, encoding: .utf8)
    }

    /// Accepts IEEE oui.csv ("MA-L,286FB9,Nokia,\"addr\""), nmap-mac-prefixes ("286FB9 Nokia")
    /// and our own normalized format ("286FB9<TAB>Nokia").
    static func parse(_ text: String) -> [UInt32: String] {
        var out: [UInt32: String] = [:]
        out.reserveCapacity(40_000)
        for line in text.split(whereSeparator: \.isNewline) {
            if line.hasPrefix("#") { continue }
            if line.hasPrefix("MA-L,") {
                let f = csvFields(line, limit: 3)
                if f.count >= 3, f[1].count == 6, let k = UInt32(f[1], radix: 16) {
                    out[k] = f[2].trimmingCharacters(in: .whitespaces)
                }
                continue
            }
            let hex = line.prefix(6)
            guard hex.count == 6, let k = UInt32(hex, radix: 16) else { continue }
            let rest = line.dropFirst(6).trimmingCharacters(in: .whitespaces)
            if !rest.isEmpty { out[k] = rest }
        }
        return out
    }

    private static func csvFields(_ line: Substring, limit: Int) -> [String] {
        var fields: [String] = []
        var cur = ""
        var inQuotes = false
        for ch in line {
            if ch == "\"" {
                inQuotes.toggle()
            } else if ch == "," && !inQuotes {
                fields.append(cur)
                cur = ""
                if fields.count == limit { return fields }
            } else {
                cur.append(ch)
            }
        }
        fields.append(cur)
        return fields
    }
}
