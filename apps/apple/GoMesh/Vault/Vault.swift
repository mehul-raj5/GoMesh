@preconcurrency import GoMeshCore
import CryptoKit
import Foundation
import Security

/// Where the vault keeps its items: the Keychain, or, only in an unsigned
/// Debug build on the Mac, files in the app's folder.
protocol SecretStore: Sendable {
    func read(_ name: String) throws -> Data?
    func write(_ name: String, _ data: Data) throws
    func delete(_ name: String) throws
    /// Deletes every item this app has stored: a fresh install starts clean.
    func deleteAll() throws
}

/// The engine's vault: its account key, identity keys and session token.
///
/// Items are this-device-only, never synced or backed up, and readable after
/// the first unlock so the app can reconnect in the background. Where there is
/// a Secure Enclave, every value is also sealed to a P-256 key that never
/// leaves it, so a copy of the stored item alone is useless. The simulator has
/// no Secure Enclave; there values are stored as the Keychain keeps them.
final class Vault: NSObject, BridgeVaultProtocol, @unchecked Sendable {
    enum Failure: Error, CustomStringConvertible {
        case keychain(OSStatus, String)
        case corrupt(String)
        case unavailable(String)

        var description: String {
            switch self {
            case let .keychain(status, op):
                let msg = SecCopyErrorMessageString(status, nil) as String? ?? "unknown"
                return "Keychain \(op) failed: \(status) (\(msg))"
            case let .corrupt(why): return "Vault item is corrupt: \(why)"
            case let .unavailable(why): return why
            }
        }
    }

    enum Kind: String, Sendable {
        case keychain = "Keychain"
        case developmentFiles = "Development files (unsigned Debug build)"
    }

    private static let wrappingKeyItem = "se-wrapping-key"
    private static let format: UInt8 = 1

    let store: any SecretStore
    let kind: Kind
    private let wrappingKey: SecureEnclave.P256.KeyAgreement.PrivateKey?

    var usesSecureEnclave: Bool { wrappingKey != nil }

    private init(store: any SecretStore, kind: Kind, wrappingKey: SecureEnclave.P256.KeyAgreement.PrivateKey?) {
        self.store = store
        self.kind = kind
        self.wrappingKey = wrappingKey
    }

    /// Opens the vault. The data-protection Keychain on the Mac needs a
    /// development team's signature; an unsigned Debug build keeps its items as
    /// files in `devFolder` instead, still sealed by the Secure Enclave, and a
    /// Release build refuses to run without the Keychain.
    static func open(devFolder: URL) throws -> Vault {
        let (store, kind) = try chooseStore(devFolder: devFolder)
        return try open(store: store, kind: kind)
    }

    /// The store the vault would use, for the first-launch wipe.
    static func chooseStore(devFolder: URL) throws -> (any SecretStore, Kind) {
        let keychain = KeychainStore()
        #if os(macOS)
        if keychain.probe() == errSecMissingEntitlement {
            #if DEBUG
            return (FileStore(folder: devFolder), .developmentFiles)
            #else
            throw Failure.unavailable("This build is not signed for the Keychain, so it cannot keep keys safely.")
            #endif
        }
        #endif
        return (keychain, .keychain)
    }

    static func open(store: any SecretStore, kind: Kind) throws -> Vault {
        guard SecureEnclave.isAvailable else {
            return Vault(store: store, kind: kind, wrappingKey: nil)
        }
        if let blob = try store.read(wrappingKeyItem) {
            let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: blob)
            return Vault(store: store, kind: kind, wrappingKey: key)
        }
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            nil, kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly, .privateKeyUsage, &error
        ) else {
            throw error!.takeRetainedValue() as Error
        }
        let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: access)
        // dataRepresentation is the key sealed by the Secure Enclave itself; it is
        // only usable on this device.
        try store.write(wrappingKeyItem, key.dataRepresentation)
        return Vault(store: store, kind: kind, wrappingKey: key)
    }

    // MARK: BridgeVaultProtocol

    /// Returns the secret stored under `name`, or empty data if there is none.
    /// Every other failure, a locked device included, is an error: the engine
    /// must never mistake an unreadable vault for an empty one.
    func get(_ name: String?) throws -> Data {
        let name = name ?? ""
        guard let stored = try store.read(name) else { return Data() }
        return try unwrap(stored, name: name)
    }

    func put(_ name: String?, value: Data?) throws {
        let name = name ?? ""
        try store.write(name, try wrap(value ?? Data(), name: name))
    }

    func delete(_ name: String?) throws {
        try store.delete(name ?? "")
    }

    // MARK: Secure Enclave sealing

    // Sealed layout: [format 1][ephemeral P-256 public key, x9.63, 65][AES-GCM combined].
    // The item name is bound into the key derivation, so a sealed value moved
    // under another name does not open.
    private func wrap(_ plain: Data, name: String) throws -> Data {
        guard let wrappingKey else { return plain }
        let ephemeral = P256.KeyAgreement.PrivateKey()
        let key = Self.sealingKey(
            shared: try ephemeral.sharedSecretFromKeyAgreement(with: wrappingKey.publicKey),
            ephemeral: ephemeral.publicKey, recipient: wrappingKey.publicKey, name: name
        )
        guard let box = try AES.GCM.seal(plain, using: key).combined else {
            throw Failure.corrupt("could not seal")
        }
        return Data([Self.format]) + ephemeral.publicKey.x963Representation + box
    }

    private func unwrap(_ sealed: Data, name: String) throws -> Data {
        guard let wrappingKey else { return sealed }
        let pubLen = 65
        guard sealed.count > 1 + pubLen, sealed.first == Self.format else {
            throw Failure.corrupt("unknown format")
        }
        let body = sealed.dropFirst()
        let ephemeral = try P256.KeyAgreement.PublicKey(x963Representation: body.prefix(pubLen))
        let key = Self.sealingKey(
            shared: try wrappingKey.sharedSecretFromKeyAgreement(with: ephemeral),
            ephemeral: ephemeral, recipient: wrappingKey.publicKey, name: name
        )
        return try AES.GCM.open(AES.GCM.SealedBox(combined: body.dropFirst(pubLen)), using: key)
    }

    private static func sealingKey(
        shared: SharedSecret, ephemeral: P256.KeyAgreement.PublicKey,
        recipient: P256.KeyAgreement.PublicKey, name: String
    ) -> SymmetricKey {
        shared.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: ephemeral.x963Representation + recipient.x963Representation,
            sharedInfo: Data("GoMesh-vault-v1|\(name)".utf8),
            outputByteCount: 32
        )
    }
}

/// Items in the data-protection Keychain: this device only, after first unlock.
struct KeychainStore: SecretStore {
    static let service = "com.mehulraj.gomesh.vault"

    private func query(_ name: String?) -> [String: Any] {
        var q: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: Self.service,
            kSecAttrSynchronizable as String: false,
            kSecUseDataProtectionKeychain as String: true,
        ]
        if let name { q[kSecAttrAccount as String] = name }
        return q
    }

    /// errSecMissingEntitlement on a Mac build without a team's signature.
    func probe() -> OSStatus {
        SecItemDelete(query("probe") as CFDictionary)
    }

    func read(_ name: String) throws -> Data? {
        var q = query(name)
        q[kSecReturnData as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        var out: CFTypeRef?
        let status = SecItemCopyMatching(q as CFDictionary, &out)
        switch status {
        case errSecSuccess:
            guard let data = out as? Data else { throw Vault.Failure.corrupt("not data") }
            return data
        case errSecItemNotFound: return nil
        default: throw Vault.Failure.keychain(status, "read")
        }
    }

    /// Updates the item in place, or adds it: there is never a moment when the
    /// secret is in neither the old item nor the new one.
    func write(_ name: String, _ data: Data) throws {
        let update: [String: Any] = [
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        ]
        var status = SecItemUpdate(query(name) as CFDictionary, update as CFDictionary)
        if status == errSecItemNotFound {
            var add = query(name)
            add.merge(update) { $1 }
            status = SecItemAdd(add as CFDictionary, nil)
        }
        guard status == errSecSuccess else { throw Vault.Failure.keychain(status, "write") }
    }

    func delete(_ name: String) throws {
        let status = SecItemDelete(query(name) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw Vault.Failure.keychain(status, "delete")
        }
    }

    func deleteAll() throws {
        let status = SecItemDelete(query(nil) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw Vault.Failure.keychain(status, "delete all")
        }
    }
}

/// Items as 0600 files, for an unsigned Debug build on the Mac only, where the
/// data-protection Keychain is out of reach and the legacy one would ask for a
/// password after every rebuild. Values are still sealed by the Secure Enclave.
struct FileStore: SecretStore {
    let folder: URL

    private func url(_ name: String) throws -> URL {
        guard !name.isEmpty, name.allSatisfy({ $0.isLetter || $0.isNumber || $0 == "-" || $0 == "." }),
              !name.hasPrefix(".") else {
            throw Vault.Failure.corrupt("bad item name \(name)")
        }
        return folder.appendingPathComponent(name)
    }

    func read(_ name: String) throws -> Data? {
        do {
            return try Data(contentsOf: try url(name))
        } catch let error as CocoaError where error.code == .fileReadNoSuchFile {
            return nil
        }
    }

    func write(_ name: String, _ data: Data) throws {
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true,
                                                attributes: [.posixPermissions: 0o700])
        let target = try url(name)
        try data.write(to: target, options: [.atomic])
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: target.path)
    }

    func delete(_ name: String) throws {
        do {
            try FileManager.default.removeItem(at: try url(name))
        } catch let error as CocoaError where error.code == .fileNoSuchFile {
        }
    }

    func deleteAll() throws {
        do {
            try FileManager.default.removeItem(at: folder)
        } catch let error as CocoaError where error.code == .fileNoSuchFile {
        }
    }
}
