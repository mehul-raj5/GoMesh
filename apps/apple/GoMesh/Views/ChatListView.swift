import SwiftUI

/// The chats: the signed-in account's, newest first, then, read-only, any kept
/// on this device for accounts that are not signed in.
struct ChatListView: View {
    @Environment(AppState.self) private var app
    @Environment(\.theme) private var theme
    @Binding var selection: ChatSelection?
    @Binding var search: String
    #if os(macOS)
    @FocusState private var focused: Bool
    #endif

    var body: some View {
        #if os(macOS)
        macList
        #else
        phoneList
        #endif
    }

    private func liveRow(_ c: ChatSummary) -> ChatRow {
        ChatRow(name: c.name, isGroup: c.isGroup, preview: preview(c), date: c.lastDate,
                unread: c.unread, readOnly: c.readOnly, selected: selection == .live(c.id),
                tick: c.previewFromMe ? c.previewDelivery.map { TickState(status: "sent", delivery: $0) } : nil)
    }

    private func keptRow(_ account: String, _ k: KeptChat) -> ChatRow {
        ChatRow(name: k.name, isGroup: k.isGroup, preview: keptPreview(k), date: k.lastDate, unread: 0,
                readOnly: true, selected: selection == .kept(account: account, chat: k.id))
    }

    private func earlierHeader(_ account: HistoryAccount) -> some View {
        Text("Earlier on this device · \(account.username)")
            .font(.caption.weight(.semibold))
            .foregroundStyle(theme.textMuted)
            .padding(.horizontal, 6)
    }

    #if os(macOS)
    /// The chats as plain rows in a scroll view rather than a `List`: the Mac's
    /// list draws its own highlight in the system accent, which the rounded bar
    /// in the theme's `selectedRow` would have to fight. Up and down move the
    /// selection, as they do in a list.
    private var macList: some View {
        let chats = filtered(app.chats)
        let order: [ChatSelection] = chats.map { .live($0.id) }
            + app.earlier.flatMap { g in g.chats.filter { matches($0.name) }.map { ChatSelection.kept(account: g.account.id, chat: $0.id) } }
        return ScrollView {
            LazyVStack(spacing: 0) {
                if chats.isEmpty && app.earlier.isEmpty { empty }
                ForEach(chats) { c in
                    Button { selection = .live(c.id); focused = true } label: { liveRow(c) }
                        .buttonStyle(.plain)
                        .macRowBar(selected: selection == .live(c.id))
                }
                ForEach(app.earlier, id: \.account.id) { group in
                    let kept = group.chats.filter { matches($0.name) }
                    if !kept.isEmpty {
                        earlierHeader(group.account).frame(maxWidth: .infinity, alignment: .leading).padding(.top, 12)
                        ForEach(kept) { k in
                            Button { selection = .kept(account: group.account.id, chat: k.id); focused = true } label: { keptRow(group.account.id, k) }
                                .buttonStyle(.plain)
                                .macRowBar(selected: selection == .kept(account: group.account.id, chat: k.id))
                        }
                    }
                }
            }
            .padding(.horizontal, 6)
            .padding(.bottom, 6)
        }
        .scrollContentBackground(.hidden)
        .focusable()
        .focusEffectDisabled()
        .focused($focused)
        .onKeyPress(.upArrow) { step(-1, in: order); return .handled }
        .onKeyPress(.downArrow) { step(1, in: order); return .handled }
    }

    private func step(_ delta: Int, in order: [ChatSelection]) {
        guard !order.isEmpty else { return }
        let at = selection.flatMap { order.firstIndex(of: $0) }
        selection = order[max(0, min(order.count - 1, (at ?? (delta > 0 ? -1 : order.count)) + delta))]
    }
    #else
    private var phoneList: some View {
        let chats = filtered(app.chats)
        return List(selection: $selection) {
            if chats.isEmpty && app.earlier.isEmpty {
                empty
                    .listRowBackground(Color.clear)
                    .listRowSeparator(.hidden)
            }
            ForEach(chats) { c in
                liveRow(c)
                    .tag(ChatSelection.live(c.id))
                    .rowChrome(selected: selection == .live(c.id))
            }
            ForEach(app.earlier, id: \.account.id) { group in
                let kept = group.chats.filter { matches($0.name) }
                if !kept.isEmpty {
                    Section {
                        ForEach(kept) { k in
                            keptRow(group.account.id, k)
                                .tag(ChatSelection.kept(account: group.account.id, chat: k.id))
                                .rowChrome(selected: selection == .kept(account: group.account.id, chat: k.id))
                        }
                    } header: {
                        earlierHeader(group.account)
                    }
                }
            }
        }
        .listStyle(.plain)
        .scrollContentBackground(.hidden)
        .background(theme.surface)
    }
    #endif

    private var empty: some View {
        VStack(spacing: 10) {
            Image(systemName: "bubble.left.and.bubble.right")
                .font(.largeTitle)
                .foregroundStyle(theme.accentText)
                .accessibilityHidden(true)
            Text(search.isEmpty ? "No chats yet" : "No chats match").font(.headline).foregroundStyle(theme.text)
            if search.isEmpty {
                Text("Start one from the menu.")
                    .font(.callout).foregroundStyle(theme.textMuted).multilineTextAlignment(.center)
            }
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 60)
    }

    private func matches(_ name: String) -> Bool {
        search.isEmpty || name.localizedCaseInsensitiveContains(search)
    }

    private func filtered(_ chats: [ChatSummary]) -> [ChatSummary] { chats.filter { matches($0.name) } }

    private func preview(_ c: ChatSummary) -> String {
        if c.preview.isEmpty { return c.isGroup ? String(localized: "Group") : String(localized: "No messages yet") }
        let body = c.previewIsFile ? "📎 " + c.preview : c.preview
        return c.previewFromMe ? String(localized: "You: ") + body : body
    }

    private func keptPreview(_ k: KeptChat) -> String {
        guard let p = k.preview, !p.isEmpty else { return String(localized: "\(k.messages) messages") }
        let body = (k.previewIsFile ?? false) ? "📎 " + p : p
        return (k.previewFromMe ?? false) ? String(localized: "You: ") + body : body
    }
}

#if os(macOS)
private extension View {
    /// The selected row is a rounded bar in the theme's `selectedRow`.
    func macRowBar(selected: Bool) -> some View { modifier(MacRowBar(selected: selected)) }
}

private struct MacRowBar: ViewModifier {
    @Environment(\.theme) private var theme
    let selected: Bool

    func body(content: Content) -> some View {
        content
            .background(selected ? theme.selectedRow : Color.clear, in: RoundedRectangle(cornerRadius: 14, style: .continuous))
            .contentShape(Rectangle())
            .accessibilityAddTraits(selected ? [.isButton, .isSelected] : .isButton)
    }
}
#endif

/// The list row around a chat: no separator, and the selected one a solid
/// rounded bar in the theme's `selectedRow`.
#if os(iOS)
private extension View {
    func rowChrome(selected: Bool) -> some View {
        modifier(RowChrome(selected: selected))
    }
}
#endif

#if os(iOS)
private struct RowChrome: ViewModifier {
    @Environment(\.theme) private var theme
    let selected: Bool

    @ViewBuilder private var bar: some View {
        RoundedRectangle(cornerRadius: 12, style: .continuous)
            .fill(selected ? theme.selectedRow : Color.clear)
            .padding(.horizontal, 6)
            .padding(.vertical, 1)
    }

    func body(content: Content) -> some View {
        content
            .listRowInsets(EdgeInsets())
            .listRowSeparator(.hidden)
            .listRowBackground(bar)
    }
}
#endif

struct ChatRow: View {
    @Environment(\.theme) private var theme
    let name: String
    let isGroup: Bool
    let preview: String
    let date: Date?
    let unread: Int64
    let readOnly: Bool
    var selected = false
    /// The ticks for your own last message, when the engine reports them.
    var tick: TickState?
    @ScaledMetric(relativeTo: .body) private var avatar: CGFloat = 52

    /// Everything on the selected row is `onSelectedRow`, at full strength.
    private var ink: Color { selected ? theme.onSelectedRow : theme.text }
    private var quiet: Color { selected ? theme.onSelectedRow : theme.textMuted }

    var body: some View {
        HStack(spacing: 12) {
            Avatar(name: name, isGroup: isGroup, size: avatar, onSelectedRow: selected)
            VStack(alignment: .leading, spacing: 3) {
                HStack(alignment: .firstTextBaseline) {
                    Text(name)
                        .font(.body.weight(.bold))
                        .foregroundStyle(ink)
                        .lineLimit(1)
                    Spacer(minLength: 6)
                    if let tick {
                        TickView(state: tick, plain: selected ? theme.onSelectedRow : theme.textMuted,
                                 read: selected ? theme.onSelectedRow : theme.accentText)
                    }
                    if let date {
                        Text(ChatFormat.listTime(date))
                            .font(.caption)
                            .foregroundStyle(unread > 0 && !selected ? theme.accentText : quiet)
                    }
                }
                HStack(alignment: .firstTextBaseline) {
                    Text(preview)
                        .font(.subheadline)
                        .foregroundStyle(quiet)
                        .lineLimit(2)
                    Spacer(minLength: 6)
                    if unread > 0 {
                        Text(unread > 99 ? "99+" : "\(unread)")
                            .font(.caption2.weight(.bold))
                            .foregroundStyle(selected ? theme.selectedRow : theme.onAccent)
                            .padding(.horizontal, 6)
                            .frame(minWidth: 22, minHeight: 22)
                            .background(selected ? theme.onSelectedRow : theme.accent, in: Capsule())
                            .accessibilityLabel("\(unread) unread")
                    } else if readOnly {
                        Image(systemName: "lock.fill").font(.caption2).foregroundStyle(quiet)
                            .accessibilityLabel("Read only")
                    }
                }
            }
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 8)
        .contentShape(Rectangle())
        .accessibilityElement(children: .combine)
    }
}
