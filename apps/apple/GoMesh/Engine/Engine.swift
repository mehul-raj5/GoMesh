@preconcurrency import GoMeshCore
import Foundation

/// An error from the engine, with the bridge's stable code.
struct EngineError: Error, Sendable, Equatable {
    var code: String
    var message: String

    init(code: String, message: String) {
        self.code = code
        self.message = message
    }

    /// The bridge's errors arrive as an NSError whose description is JSON.
    init(_ error: Error) {
        let text = (error as NSError).localizedDescription
        if let data = text.data(using: .utf8),
           let decoded = try? JSONDecoder().decode(Wire.self, from: data) {
            self.init(code: decoded.code, message: decoded.message)
        } else {
            self.init(code: "internal", message: text)
        }
    }

    private struct Wire: Decodable { var code: String; var message: String }
}

struct Account: Decodable, Sendable, Equatable {
    var userID: String
    var username: String
}

struct SavedSession: Decodable, Sendable, Equatable {
    var server: String
    var username: String
}

struct ServerCheck: Decodable, Sendable, Equatable {
    var address: String
    var fingerprint: String
    var fingerprintGroups: String
    var pinned: Bool
}

struct Conversation: Decodable, Sendable, Identifiable, Equatable {
    var id: String
    var name: String
    var isGroup: Bool
    var isAdmin: Bool

    /// The chat's name as people read it: a private chat is its person.
    var title: String {
        name.hasPrefix("Private Chat: ") ? String(name.dropFirst("Private Chat: ".count)) : name
    }
}

/// A chat as the chat list shows it.
struct ChatSummary: Decodable, Sendable, Identifiable, Equatable {
    var id: String
    var name: String
    var isGroup: Bool
    var isAdmin: Bool
    var lastTime: Int64
    var preview: String
    var previewIsFile: Bool
    var previewFromMe: Bool
    /// The delivery of the last message when it is yours, as `ChatMessage.delivery`.
    /// Optional: absent until the engine reports it.
    var previewDelivery: String?
    var unread: Int64
    var readOnly: Bool

    var lastDate: Date? { lastTime == 0 ? nil : Date(timeIntervalSince1970: Double(lastTime) / 1000) }
}

/// An account with chats kept on this device; only the signed-in one can send.
struct HistoryAccount: Decodable, Sendable, Identifiable, Equatable {
    var id: String
    var username: String
    var current: Bool
}

/// A chat kept on this device for an account that is not signed in.
struct KeptChat: Decodable, Sendable, Identifiable, Equatable {
    var id: String
    var name: String
    var isGroup: Bool
    var messages: Int64
    var lastTime: Int64
    var preview: String?
    var previewIsFile: Bool?
    var previewFromMe: Bool?

    var lastDate: Date? { lastTime == 0 ? nil : Date(timeIntervalSince1970: Double(lastTime) / 1000) }
}

struct MediaInfo: Decodable, Sendable, Equatable {
    var fileName: String
    var fileType: String?
    var size: Int64
    var mediaID: String?
    /// A small JPEG for an image, base64 in the JSON.
    var thumbnail: Data?
}

/// Someone in a group, as its signed log has them.
struct GroupMember: Decodable, Sendable, Identifiable, Equatable {
    var id: String
    var name: String
    var isAdmin: Bool
    var isMe: Bool
}

/// A message as this device keeps it.
struct ChatMessage: Decodable, Sendable, Identifiable, Equatable {
    var seq: Int64
    var convID: String
    var sender: String?
    var senderName: String?
    var outgoing: Bool
    var time: Int64
    var text: String?
    var media: MediaInfo?
    var system: Bool?
    /// "queued", "sent" or "failed": what this device knows.
    var status: String
    /// What the receipts say, once the engine reports them: "pending",
    /// "accepted", "delivered" or "read". Absent from an engine without
    /// receipts, and from incoming messages.
    var delivery: String?
    /// For a group, how many recipients have the message and have read it, of
    /// `total`.
    var deliveredCount: Int?
    var readCount: Int?
    var total: Int?

    var id: Int64 { seq }
    var date: Date { Date(timeIntervalSince1970: Double(time) / 1000) }
    var isSystem: Bool { system ?? false }
}

/// What the engine reports, decoded from its JSON.
struct EngineEvent: Sendable {
    enum Kind: String, Sendable {
        case notice, message, progress, connection, signedOut, passwordRequired, mediaSaved, messageStatus
    }

    struct Payload: Decodable, Sendable {
        var level: String?
        var text: String?
        var convID: String?
        var sender: String?
        var senderName: String?
        var time: Int64?
        var progress: Double?
        var state: String?
        var mediaID: String?
        var seq: Int64?
        var status: String?
        var delivery: String?
        var deliveredCount: Int?
        var readCount: Int?
        var total: Int?
        var transfer: String?
    }

    var kind: Kind
    var payload: Payload

    init?(kind: String, payload: String) {
        guard let k = Kind(rawValue: kind),
              let p = try? JSONDecoder().decode(Payload.self, from: Data(payload.utf8)) else { return nil }
        self.kind = k
        self.payload = p
    }
}

/// The Go engine, called off the main thread. Every method that can touch the
/// network is async and runs on a background task; the engine's own events
/// arrive through `events`, on the main actor, in order.
final class Engine: @unchecked Sendable {
    private let engine: BridgeEngine
    private let sink: EventSink

    /// Opens the device in `dataDir`. `onEvent` runs on the main actor.
    init(dataDir: URL, deviceName: String, vault: Vault,
         onEvent: @escaping @MainActor @Sendable (EngineEvent) -> Void) throws {
        try FileManager.default.createDirectory(at: dataDir, withIntermediateDirectories: true,
                                                attributes: [.posixPermissions: 0o700])
        let sink = EventSink(onEvent)
        var err: NSError?
        guard let engine = BridgeNewEngine(dataDir.path, deviceName, vault, sink, &err) else {
            throw EngineError(err ?? NSError(domain: "go", code: 0))
        }
        self.engine = engine
        self.sink = sink
    }

    private func background<T: Sendable>(_ body: @escaping @Sendable () throws -> T) async throws -> T {
        do {
            return try await Task.detached(priority: .userInitiated) { try body() }.value
        } catch let e as EngineError {
            throw e
        } catch {
            throw EngineError(error)
        }
    }

    private func string(_ call: (NSErrorPointer) -> String) throws -> String {
        var err: NSError?
        let out = call(&err)
        if let err { throw EngineError(err) }
        return out
    }

    private func decode<T: Decodable>(_ type: T.Type, _ json: String) throws -> T {
        do {
            return try JSONDecoder().decode(type, from: Data(json.utf8))
        } catch {
            throw EngineError(code: "internal", message: "Unreadable answer from the engine: \(error)")
        }
    }

    var savedSession: SavedSession? {
        let s = engine.savedSession()
        return s.isEmpty ? nil : try? decode(SavedSession.self, s)
    }

    func checkServer(_ address: String) async throws -> ServerCheck {
        let json = try await background { [self] in try string { engine.checkServer(address, error: $0) } }
        return try decode(ServerCheck.self, json)
    }

    func trustServer(_ address: String, fingerprint: String) async throws {
        try await background { [self] in try engine.trustServer(address, fingerprint: fingerprint) }
    }

    func forgetServer(_ address: String) async throws {
        try await background { [self] in try engine.forgetServer(address) }
    }

    func register(server: String, username: String, password: String) async throws {
        try await background { [self] in try engine.register(server, username: username, password: password) }
    }

    func login(server: String, username: String, password: String) async throws {
        try await background { [self] in try engine.login(server, username: username, password: password) }
    }

    func resume() async throws {
        try await background { [self] in try engine.resume() }
    }

    func logout(deleteHistory: Bool) async {
        _ = try? await background { [self] in engine.logout(deleteHistory) }
    }

    func account() throws -> Account {
        try decode(Account.self, try string { engine.account($0) })
    }

    func conversations() throws -> [Conversation] {
        try decode([Conversation].self, try string { engine.conversations($0) })
    }

    func chatList() async throws -> [ChatSummary] {
        let json = try await background { [self] in try string { engine.chatList($0) } }
        return try decode([ChatSummary].self, json)
    }

    func historyAccounts() async throws -> [HistoryAccount] {
        let json = try await background { [self] in try string { engine.historyAccounts($0) } }
        return try decode([HistoryAccount].self, json)
    }

    func keptChats(account: String) async throws -> [KeptChat] {
        let json = try await background { [self] in try string { engine.historyConversations(account, error: $0) } }
        return try decode([KeptChat].self, json)
    }

    /// Up to `limit` messages before `before` (0 for the newest), oldest first.
    func messages(account: String, chat: String, before: Int64 = 0, limit: Int = 50) async throws -> [ChatMessage] {
        let json = try await background { [self] in
            try string { engine.messages(account, convID: chat, before: before, limit: limit, error: $0) }
        }
        return try decode([ChatMessage].self, json)
    }

    func sendText(chat: String, text: String) async throws {
        try await background { [self] in try engine.sendText(chat, text: text) }
    }

    func markRead(chat: String) async {
        _ = try? await background { [self] in try engine.markRead(chat) }
    }

    /// The private chat with `username`, opened if there is none.
    func openDirect(_ username: String) async throws -> String {
        try await background { [self] in try string { engine.openDirect(username, error: $0) } }
    }

    /// Makes a group and returns its ID once the server has taken it.
    func createGroup(name: String, members: [String]) async throws -> String {
        let json = String(decoding: try JSONEncoder().encode(members), as: UTF8.self)
        return try await background { [self] in try string { engine.createGroup(name, members: json, error: $0) } }
    }

    func groupMembers(_ group: String) async throws -> [GroupMember] {
        let json = try await background { [self] in try string { engine.groupMembers(group, error: $0) } }
        return try decode([GroupMember].self, json)
    }

    enum GroupAction: String, Sendable { case add, remove, makeAdmin, removeAdmin, leave }

    func groupAction(_ group: String, _ action: GroupAction, username: String = "") async throws {
        try await background { [self] in try engine.groupAction(group, action: action.rawValue, username: username) }
    }

    /// Sends the file at `path`, which must stay until the transfer ends, and
    /// returns the transfer's ID.
    func sendFile(chat: String, path: String) async throws -> String {
        try await background { [self] in try string { engine.sendFile(chat, path: path, error: $0) } }
    }

    /// Writes a kept file out, decrypted, into `dir`, and returns where.
    func exportMedia(account: String, mediaID: String, fileName: String, dir: URL) async throws -> URL {
        let path = try await background { [self] in
            try string { engine.exportMedia(account, mediaID: mediaID, fileName: fileName, dir: dir.path, error: $0) }
        }
        return URL(fileURLWithPath: path)
    }

    func restartChat(_ chat: String) async throws {
        try await background { [self] in try engine.restartChat(chat) }
    }

    func safetyNumber(_ chat: String) async throws -> String {
        try await background { [self] in try string { engine.safetyNumber(chat, error: $0) } }
    }

    /// Whether this device tells people when it has read their messages. On by
    /// default in the engine; off, they never see coloured ticks for you.
    func setSendReadReceipts(_ on: Bool) {
        engine.setSendReadReceipts(on)
    }

    func setForeground(_ foreground: Bool) {
        engine.setForeground(foreground)
    }

    /// Disconnects until setForeground(true), after telling the server what has
    /// been read, so nothing sent meanwhile is lost with the socket iOS takes
    /// away in the background.
    func pause() async {
        _ = try? await background { [self] in engine.pause() }
    }

    /// Closes the engine and waits for its loops; call it before opening the
    /// same folder again.
    func close() async {
        _ = try? await background { [self] in engine.close() }
    }

    static func normalize(_ address: String) -> String { BridgeNormalizeAddress(address) }
}

/// Receives the engine's events on its goroutine and hands each to the main
/// actor without waiting, so the engine is never held up by the UI and a call
/// into the engine from the main thread can never deadlock against it.
private final class EventSink: NSObject, BridgeEventHandlerProtocol, @unchecked Sendable {
    private let deliver: @MainActor @Sendable (EngineEvent) -> Void

    init(_ deliver: @escaping @MainActor @Sendable (EngineEvent) -> Void) {
        self.deliver = deliver
    }

    func onEvent(_ kind: String?, payload: String?) {
        guard let event = EngineEvent(kind: kind ?? "", payload: payload ?? "{}") else { return }
        let deliver = self.deliver
        DispatchQueue.main.async {
            MainActor.assumeIsolated { deliver(event) }
        }
    }
}
