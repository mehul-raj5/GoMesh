import Foundation
import Observation
import SwiftUI
#if canImport(UIKit)
import UIKit
#endif

/// The app's state: which screen, who is signed in, how the connection is.
/// Everything here lives on the main actor; the engine's work runs on
/// background tasks and its events arrive here in order.
@MainActor @Observable
final class AppState {
    enum Phase: Equatable {
        case launching
        case failed(String)
        case welcome
        case auth(AuthMode)
        case signedIn
    }

    enum AuthMode: Equatable { case create, signIn }

    enum Connection: Equatable {
        case offline, connecting, online
    }

    var phase: Phase = .launching
    var connection: Connection = .offline
    /// A line about the connection worth showing, such as why it is down.
    var connectionText = ""
    var account: Account?
    var server = AppState.defaultServer
    /// The signed-in account's chats, newest first.
    var chats: [ChatSummary] = []
    /// Chats kept on this device for accounts that are not signed in: readable,
    /// never writable.
    var earlier: [(account: HistoryAccount, chats: [KeptChat])] = []
    /// The chat on screen, if any.
    var selectedChat: String?
    /// Whether the app is in front, so a chat on screen counts as read.
    var isActive = true
    /// Files on their way, by transfer ID.
    var transfers: [String: Transfer] = [:]
    /// The temporary copy each outgoing transfer is reading.
    private var outgoingCopies: [String: URL] = [:]
    /// Transfers already over, which a late `sendFile` return must not revive.
    private var finishedTransfers: Set<String> = []

    /// A chat to bring on screen, such as one a notification was tapped for.
    var requestedChat: String?
    /// A menu command for the home screen to carry out.
    var command: AppCommand?

    enum AppCommand: Equatable { case newChat, newGroup, search }

    /// The largest file the engine takes.
    static let maxFileSize: Int64 = 50 << 20
    /// Something to tell the person on the auth screens: why they are here.
    var authNotice: String?
    /// The username to put in the sign-in form.
    var suggestedUsername = ""
    /// A short-lived message: a notice from the engine.
    var toast: String?
    var vaultDescription = ""
    /// Whether this device tells people when it has read their messages.
    /// Kept across launches; applied to the engine whenever one opens.
    var sendReadReceipts = UserDefaults.standard.object(forKey: "sendReadReceipts") as? Bool ?? true {
        didSet {
            UserDefaults.standard.set(sendReadReceipts, forKey: "sendReadReceipts")
            engine?.setSendReadReceipts(sendReadReceipts)
        }
    }

    /// The server the sign-in screen suggests: GOMESH_DEFAULT_SERVER from the
    /// build settings (see Config/Base.xcconfig), or a server on this machine.
    static let defaultServer: String = {
        let configured = (Bundle.main.object(forInfoDictionaryKey: "GoMeshDefaultServer") as? String)?
            .trimmingCharacters(in: .whitespaces) ?? ""
        return configured.isEmpty ? "localhost:8080" : configured
    }()

    private(set) var engine: Engine?
    private var vault: Vault?
    private var folder: AppFolder?
    private var generation = 0 // events from a closed engine are dropped
    private var signingOut = false
    private var models: [String: ConversationModel] = [:]
    private var chatRefresh: Task<Void, Never>?

    // MARK: launch

    private var launched = false

    func launch() async {
        guard !launched else { return }
        launched = true
        Notifier.shared.start(app: self)
        TempFiles.clearAll()
        do {
            let folder = try AppFolder.locate()
            let (store, kind) = try Vault.chooseStore(devFolder: folder.devVault)
            _ = try folder.prepare { try store.deleteAll() }
            let vault = try Vault.open(store: store, kind: kind)
            self.folder = folder
            self.vault = vault
            vaultDescription = vault.kind.rawValue + (vault.usesSecureEnclave ? ", sealed by the Secure Enclave" : "")
            try openEngine()
        } catch let e as EngineError {
            phase = .failed(e.message)
            return
        } catch {
            phase = .failed("GoMesh could not open its storage on this device: \(error)")
            return
        }
        await resumeIfSaved()
    }

    private func openEngine() throws {
        guard let folder, let vault else { return }
        generation += 1
        let mine = generation
        engine = try Engine(dataDir: folder.engineData, deviceName: Self.deviceName, vault: vault) { [weak self] event in
            guard let self, self.generation == mine else { return }
            self.handle(event)
        }
        engine?.setSendReadReceipts(sendReadReceipts)
    }

    private func resumeIfSaved() async {
        guard let engine else { return }
        guard let saved = engine.savedSession else {
            phase = .welcome
            return
        }
        server = saved.server
        suggestedUsername = saved.username
        do {
            try await engine.resume()
            enterSignedIn()
        } catch let e as EngineError {
            // The server said no, or its certificate is no longer trusted: the
            // password is the way back in. (An unreachable server is not an
            // error here; the engine starts offline and keeps trying.)
            authNotice = e.message
            phase = .auth(.signIn)
        } catch {
            phase = .auth(.signIn)
        }
    }

    // MARK: signing in

    /// The first step of signing in: what the server's certificate is, and
    /// whether it is already trusted.
    func checkServer(_ address: String) async throws -> ServerCheck {
        guard let engine else { throw EngineError(code: "closed", message: "Not ready.") }
        return try await engine.checkServer(address)
    }

    func trust(_ check: ServerCheck) async throws {
        guard let engine else { throw EngineError(code: "closed", message: "Not ready.") }
        try await engine.trustServer(check.address, fingerprint: check.fingerprint)
    }

    func forgetServer(_ address: String) async throws {
        guard let engine else { return }
        try await engine.forgetServer(Engine.normalize(address))
    }

    func submit(_ mode: AuthMode, server: String, username: String, password: String) async throws {
        guard let engine else { throw EngineError(code: "closed", message: "Not ready.") }
        let address = Engine.normalize(server)
        switch mode {
        case .create: try await engine.register(server: address, username: username, password: password)
        case .signIn: try await engine.login(server: address, username: username, password: password)
        }
        self.server = address
        authNotice = nil
        enterSignedIn()
    }

    private func enterSignedIn() {
        account = try? engine?.account()
        Notifier.shared.requestPermission()
        models = [:]
        selectedChat = nil
        transfers = [:]
        refreshChats()
        Task { await loadEarlier() }
        phase = .signedIn
    }

    /// Refreshes the chat list soon, coalescing a burst of events into one
    /// fetch, which runs off the main thread.
    func refreshChats() {
        chatRefresh?.cancel()
        chatRefresh = Task { [weak self] in
            try? await Task.sleep(for: .milliseconds(120))
            guard !Task.isCancelled, let self, let engine = self.engine else { return }
            if let list = try? await engine.chatList() {
                self.chats = list
                Notifier.shared.setBadge(Int(list.reduce(0) { $0 + $1.unread }))
            }
        }
    }

    private func loadEarlier() async {
        guard let engine, let me = account?.userID else { return }
        var out: [(account: HistoryAccount, chats: [KeptChat])] = []
        for acct in (try? await engine.historyAccounts()) ?? [] where acct.id != me {
            let chats = (try? await engine.keptChats(account: acct.id)) ?? []
            if !chats.isEmpty { out.append((acct, chats)) }
        }
        earlier = out
    }

    /// The model of a chat, made the first time it is opened.
    func model(for chatID: String, account accountID: String? = nil, readOnly: Bool = false) -> ConversationModel {
        // Two accounts on one device that chatted share a chat ID, so the
        // account is part of the key.
        let acct = accountID ?? account?.userID ?? ""
        let key = acct + "|" + chatID
        if let m = models[key] { return m }
        let m = ConversationModel(chatID: chatID, accountID: acct, readOnly: readOnly, app: self)
        models[key] = m
        return m
    }

    /// The chat on screen was read.
    func markRead(_ chatID: String) {
        guard let engine else { return }
        // The list may not have caught up with the message yet, so the engine is
        // told whatever the list says.
        if let i = chats.firstIndex(where: { $0.id == chatID }) { chats[i].unread = 0 }
        Notifier.shared.clear(chatID: chatID)
        Task {
            await engine.markRead(chat: chatID)
            self.refreshChats()
        }
    }

    /// Something happened in a chat: show it if it is loaded, and count it read
    /// if it is on screen.
    private func chatChanged(_ chatID: String?) {
        if let chatID, let m = models[(account?.userID ?? "") + "|" + chatID] {
            Task {
                await m.loadLatest()
                if chatID == self.selectedChat, self.isActive { self.markRead(chatID) }
            }
        }
        refreshChats()
    }

    /// Sends a file picked by the person: copied into the app's own folder
    /// first, and the copy deleted once the transfer ends.
    func sendFile(_ picked: URL, to chatID: String) async throws {
        guard let engine else { throw EngineError(code: "closed", message: "Not ready.") }
        let copy = try TempFiles.copyPicked(picked)
        try await sendCopy(copy, to: chatID, engine: engine)
    }

    /// Sends data the app produced, such as a photo, under `fileName`.
    func sendData(_ data: Data, fileName: String, to chatID: String) async throws {
        guard let engine else { throw EngineError(code: "closed", message: "Not ready.") }
        let copy = try TempFiles.folder("outgoing").appendingPathComponent(fileName)
        try data.write(to: copy, options: [.atomic, .completeFileProtection])
        try await sendCopy(copy, to: chatID, engine: engine)
    }

    private func sendCopy(_ copy: URL, to chatID: String, engine: Engine) async throws {
        let size = (try? copy.resourceValues(forKeys: [.fileSizeKey]).fileSize).map(Int64.init) ?? 0
        guard size <= Self.maxFileSize else {
            TempFiles.discard(copy)
            throw EngineError(code: "file_too_large", message: "Files can be at most 50 MB.")
        }
        do {
            let id = try await engine.sendFile(chat: chatID, path: copy.path)
            if finishedTransfers.contains(id) { // over before we heard back
                TempFiles.discard(copy)
                return
            }
            outgoingCopies[id] = copy
            if transfers[id] == nil {
                transfers[id] = Transfer(id: id, chatID: chatID, fileName: copy.lastPathComponent,
                                         incoming: false, progress: 0, failed: false)
            }
        } catch {
            TempFiles.discard(copy)
            throw error
        }
    }

    func dismissTransfer(_ id: String) { transfers[id] = nil }

    private func transferMoved(_ p: EngineEvent.Payload) {
        guard let id = p.transfer, let chat = p.convID else { return }
        let progress = p.progress ?? 0
        var t = transfers[id] ?? Transfer(id: id, chatID: chat, fileName: p.text ?? "", incoming: p.sender != nil,
                                          progress: 0, failed: false)
        if progress < 0 {
            t.failed = true
            transfers[id] = t
        } else if progress >= 1 {
            transfers[id] = nil
            chatChanged(chat)
        } else {
            t.progress = progress
            transfers[id] = t
        }
        if progress < 0 || progress >= 1 {
            finishedTransfers.insert(id)
            if let copy = outgoingCopies.removeValue(forKey: id) { TempFiles.discard(copy) }
        }
    }

    func openDirect(_ username: String) async throws -> String {
        guard let engine else { throw EngineError(code: "closed", message: "Not ready.") }
        let id = try await engine.openDirect(username)
        refreshChats()
        return id
    }

    // MARK: signing out

    func signOut(deleteHistory: Bool) async {
        guard let engine else { return }
        signingOut = true
        await engine.logout(deleteHistory: deleteHistory)
        // The signedOut event finishes the job.
    }

    /// The engine is spent once it signs out: close it, open a fresh one on the
    /// same folder, and start over.
    private func restart(notice: String?, toSignIn: Bool) {
        let old = engine
        engine = nil
        generation += 1
        account = nil
        // What the system shows of the old account goes with it.
        Notifier.shared.clearAll()
        chats = []
        earlier = []
        models = [:]
        selectedChat = nil
        connection = .offline
        connectionText = ""
        Task {
            await old?.close()
            do {
                try openEngine()
                authNotice = notice
                phase = toSignIn ? .auth(.signIn) : .welcome
            } catch let e as EngineError {
                phase = .failed(e.message)
            } catch {
                phase = .failed("\(error)")
            }
        }
    }

    // MARK: events

    private func handle(_ event: EngineEvent) {
        let p = event.payload
        switch event.kind {
        case .connection:
            switch p.state {
            case "online": connection = .online
            case "connecting": connection = .connecting
            default: connection = .offline
            }
            connectionText = p.text ?? ""
            if connection == .online { refreshChats() }
        case .message, .mediaSaved:
            chatChanged(p.convID)
            notifyIfUnseen(event)
        case .messageStatus:
            chatChanged(p.convID)
        case .notice:
            chatChanged(p.convID)
            // A line about a chat is shown in the chat; anything else worth
            // knowing comes up briefly.
            if p.convID == nil, p.level == "warn" || p.level == "error", let text = p.text { toast = text }
        case .progress:
            transferMoved(p)
        case .signedOut:
            // Signed out here, back to the start; signed out by the server (the
            // account moved to another device), to the sign-in form, saying why.
            let fromHere = signingOut
            signingOut = false
            if !fromHere { suggestedUsername = account?.username ?? suggestedUsername }
            restart(notice: fromHere ? nil : p.text, toSignIn: !fromHere)
        case .passwordRequired:
            // The saved session cannot be resumed; this engine has an account
            // started and cannot sign in again, so a fresh one takes the password.
            suggestedUsername = account?.username ?? suggestedUsername
            restart(notice: p.text, toSignIn: true)
        }
    }

    /// A message from someone else, in a chat not on screen, gets a
    /// notification. A file is announced once it has arrived, not before.
    private func notifyIfUnseen(_ event: EngineEvent) {
        let p = event.payload
        guard let chat = p.convID, !(isActive && selectedChat == chat) else { return }
        let fromSomeoneElse = p.sender.map { $0 != account?.userID } ?? false
        let body: String
        switch event.kind {
        case .message:
            guard fromSomeoneElse, let text = p.text, !text.isEmpty else { return }
            body = text
        case .mediaSaved:
            body = "📎 " + (p.text ?? String(localized: "File"))
        default:
            return
        }
        let sender = p.senderName ?? ""
        if let c = chats.first(where: { $0.id == chat }), c.isGroup {
            Notifier.shared.messageArrived(chatID: chat, title: c.name, body: sender.isEmpty ? body : "\(sender): \(body)")
        } else {
            Notifier.shared.messageArrived(chatID: chat, title: sender.isEmpty ? "GoMesh" : sender, body: body)
        }
    }

    /// Follows the scene. Inactive (the app switcher, Control Center, a Face ID
    /// prompt) only stops chats counting as read; going to the background on
    /// iOS also pauses the connection, which comes back as soon as the app does.
    /// The Mac stays connected, so its notifications keep coming.
    func scenePhaseChanged(_ phase: ScenePhase) {
        switch phase {
        case .active:
            isActive = true
            engine?.setForeground(true)
            if let chat = selectedChat { markRead(chat) }
        case .background:
            isActive = false
            #if os(iOS)
            pauseInBackground()
            #endif
        default:
            isActive = false
        }
    }

    #if os(iOS)
    private func pauseInBackground() {
        guard let engine, phase == .signedIn else { return }
        // A few seconds is plenty; the background task keeps iOS from suspending
        // the app before the server has heard what was read.
        let task = BackgroundTask(name: "Pause the connection")
        Task {
            await engine.pause()
            task.end()
        }
    }
    #endif

    static var deviceName: String {
        #if os(macOS)
        return Host.current().localizedName ?? "Mac"
        #else
        return UIDevice.current.name
        #endif
    }
}

#if os(iOS)
/// A stretch of work iOS lets finish after the app leaves the screen.
@MainActor
private final class BackgroundTask {
    private var id = UIBackgroundTaskIdentifier.invalid

    init(name: String) {
        id = UIApplication.shared.beginBackgroundTask(withName: name) { [weak self] in
            MainActor.assumeIsolated { self?.end() }
        }
    }

    func end() {
        guard id != .invalid else { return }
        UIApplication.shared.endBackgroundTask(id)
        id = .invalid
    }
}
#endif
