import Foundation

/// Streams the output of a system tool (ping, traceroute) into the UI.
@MainActor
final class ToolRunner: ObservableObject {
    let title: String

    @Published private(set) var output = ""
    @Published private(set) var isRunning = false

    private let path: String
    private let args: [String]
    private var process: Process?

    init(title: String, path: String, args: [String]) {
        self.title = title
        self.path = path
        self.args = args
    }

    func start() {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: path)
        p.arguments = args
        let pipe = Pipe()
        p.standardOutput = pipe
        p.standardError = pipe

        pipe.fileHandleForReading.readabilityHandler = { [weak self] handle in
            let data = handle.availableData
            guard !data.isEmpty else { return }
            let text = String(decoding: data, as: UTF8.self)
            Task { @MainActor [weak self] in self?.append(text) }
        }
        p.terminationHandler = { [weak self] proc in
            let status = Int(proc.terminationStatus)
            Task { @MainActor [weak self] in
                pipe.fileHandleForReading.readabilityHandler = nil
                self?.isRunning = false
                self?.append("\n" + String(localized: "[finished, exit code \(status)]") + "\n")
            }
        }

        output = "$ \(path) \(args.joined(separator: " "))\n"
        do {
            try p.run()
            process = p
            isRunning = true
        } catch {
            append(String(localized: "Failed to launch: \(error.localizedDescription)") + "\n")
        }
    }

    /// SIGINT, like Ctrl-C: ping prints its statistics before exiting.
    func stop() {
        if let p = process, p.isRunning { p.interrupt() }
    }

    private func append(_ s: String) {
        output += s
        if output.count > 200_000 { output = String(output.suffix(150_000)) }
    }
}
