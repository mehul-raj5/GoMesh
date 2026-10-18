import Foundation
import Observation

/// A file on its way out or in, as a chat shows it.
struct Transfer: Identifiable, Equatable {
    let id: String
    let chatID: String
    let fileName: String
    let incoming: Bool
    var progress: Double
    var failed: Bool
}

/// The app's own temporary folders: copies of files being sent, and decrypted
/// copies of files being looked at. Each is deleted when it is done with.
enum TempFiles {
    static var root: URL { FileManager.default.temporaryDirectory.appendingPathComponent("gomesh", isDirectory: true) }

    /// A fresh folder of its own under `kind`.
    static func folder(_ kind: String) throws -> URL {
        let url = root.appendingPathComponent(kind, isDirectory: true).appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true,
                                                attributes: [.posixPermissions: 0o700])
        return url
    }

    /// Removes the folder `url` was put in.
    static func discard(_ url: URL) {
        try? FileManager.default.removeItem(at: url.deletingLastPathComponent())
    }

    /// Clears whatever an earlier run left, such as a preview open when the app
    /// was quit.
    static func clearAll() {
        try? FileManager.default.removeItem(at: root)
    }

    /// Copies a picked file into a folder of the app's own, reading it under the
    /// security scope the picker granted, and returns the copy.
    static func copyPicked(_ picked: URL) throws -> URL {
        let scoped = picked.startAccessingSecurityScopedResource()
        defer { if scoped { picked.stopAccessingSecurityScopedResource() } }
        let dest = try folder("outgoing").appendingPathComponent(picked.lastPathComponent)
        try FileManager.default.copyItem(at: picked, to: dest)
        return dest
    }
}
