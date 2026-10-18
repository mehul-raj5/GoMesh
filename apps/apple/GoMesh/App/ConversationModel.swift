import Foundation
import Observation

/// A message being sent, shown until the engine keeps it, or kept here,
/// failed, for the person to retry or discard.
struct PendingMessage: Identifiable, Equatable {
    let id = UUID()
    var text: String
    var error: String?
}

/// One open chat: its messages, paged in from this device's history, newest
/// first, and what is on its way out. In memory only; the history is the
/// engine's, sealed.
@MainActor @Observable
final class ConversationModel {
    let chatID: String
    let accountID: String
    let readOnly: Bool
    private weak var app: AppState?

    private(set) var messages: [ChatMessage] = []
    private(set) var pending: [PendingMessage] = []
    private(set) var hasOlder = true
    private(set) var loadingOlder = false
    private(set) var loaded = false
    var loadError: String?
    /// What is typed and not sent yet.
    var draft = ""
    /// Counts sends that went and sends that did not, for haptic feedback.
    private(set) var sent = 0
    private(set) var failed = 0

    static let pageSize = 50

    init(chatID: String, accountID: String, readOnly: Bool, app: AppState) {
        self.chatID = chatID
        self.accountID = accountID
        self.readOnly = readOnly
        self.app = app
    }

    /// Fetches the newest page and merges it over what is loaded, so new
    /// messages and changed statuses show without losing older pages.
    func loadLatest() async {
        guard let engine = app?.engine else { return }
        do {
            let page = try await engine.messages(account: accountID, chat: chatID, limit: Self.pageSize)
            if let first = page.first {
                messages = messages.filter { $0.seq < first.seq } + page
            } else {
                messages = []
            }
            if !loaded {
                hasOlder = page.count == Self.pageSize
                loaded = true
            }
            loadError = nil
        } catch let e as EngineError {
            loadError = e.message
        } catch {}
    }

    func loadOlder() async {
        guard hasOlder, !loadingOlder, let engine = app?.engine, let oldest = messages.first else { return }
        loadingOlder = true
        defer { loadingOlder = false }
        do {
            let page = try await engine.messages(account: accountID, chat: chatID, before: oldest.seq, limit: Self.pageSize)
            messages = page + messages
            hasOlder = page.count == Self.pageSize
        } catch {}
    }

    func send(_ text: String) async {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, !readOnly else { return }
        let item = PendingMessage(text: trimmed)
        pending.append(item)
        await deliver(item)
    }

    func retry(_ item: PendingMessage) async {
        guard let i = pending.firstIndex(where: { $0.id == item.id }) else { return }
        pending[i].error = nil
        await deliver(pending[i])
    }

    func discard(_ item: PendingMessage) {
        pending.removeAll { $0.id == item.id }
    }

    private func deliver(_ item: PendingMessage) async {
        guard let engine = app?.engine else { return }
        do {
            try await engine.sendText(chat: chatID, text: item.text)
            await loadLatest() // the engine kept it; show the kept row instead
            pending.removeAll { $0.id == item.id }
            sent += 1
            app?.refreshChats()
        } catch let e as EngineError {
            if let i = pending.firstIndex(where: { $0.id == item.id }) {
                pending[i].error = e.message
            }
            failed += 1
        } catch {
            failed += 1
        }
    }
}
