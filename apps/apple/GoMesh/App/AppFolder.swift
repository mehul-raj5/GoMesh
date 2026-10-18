import Foundation

/// The app's own folder: Application Support/GoMesh. It holds the engine's
/// data directory (sealed state, the encrypted history, sealed files), is
/// excluded from backups, and on iOS is readable after the first unlock so the
/// app can reconnect in the background.
///
/// Keychain items outlive the app on iOS: deleted and reinstalled, the app
/// would find a previous install's keys with none of its state. So the first
/// launch, which is when the folder does not exist yet, deletes the vault's
/// items before anything else runs. Only a folder that is certainly missing
/// counts: any error checking for it, a locked device included, is never taken
/// for a fresh install.
struct AppFolder: Sendable {
    let root: URL

    var engineData: URL { root.appendingPathComponent("device", isDirectory: true) }
    var devVault: URL { root.appendingPathComponent("dev-vault", isDirectory: true) }

    enum Prepared: Sendable { case existing, freshInstall }

    static func locate() throws -> AppFolder {
        let base = try FileManager.default.url(for: .applicationSupportDirectory, in: .userDomainMask,
                                               appropriateFor: nil, create: true)
        return AppFolder(root: base.appendingPathComponent("GoMesh", isDirectory: true))
    }

    /// Creates the folder if it is missing and reports whether this is a fresh
    /// install. `wipe` runs before the folder is created, so a wipe that fails
    /// is tried again on the next launch.
    func prepare(wipe: () throws -> Void) throws -> Prepared {
        var isDir: ObjCBool = false
        let exists = FileManager.default.fileExists(atPath: root.path, isDirectory: &isDir)
        if exists {
            guard isDir.boolValue else { throw CocoaError(.fileWriteFileExists) }
            try protect(root)
            return .existing
        }
        // fileExists says no for an unreadable path too; only a stat that fails
        // with "no such file" proves the folder is not there.
        do {
            _ = try FileManager.default.attributesOfItem(atPath: root.path)
            return .existing // it is there after all; never wipe on doubt
        } catch let error as CocoaError where error.code == .fileReadNoSuchFile || error.code == .fileNoSuchFile {
        } catch {
            throw error
        }
        try wipe()
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true,
                                                attributes: [.posixPermissions: 0o700])
        try protect(root)
        return .freshInstall
    }

    private func protect(_ url: URL) throws {
        #if os(iOS)
        try FileManager.default.setAttributes(
            [.protectionKey: FileProtectionType.completeUntilFirstUserAuthentication], ofItemAtPath: url.path)
        #endif
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        var u = url
        try u.setResourceValues(values)
    }
}
