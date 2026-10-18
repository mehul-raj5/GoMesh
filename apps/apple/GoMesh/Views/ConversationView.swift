import SwiftUI

/// One chat: its messages, newest at the bottom, and the composer.
struct ConversationView: View {
    @Environment(AppState.self) private var app
    @Environment(AppLock.self) private var lock
    @Environment(\.theme) private var theme
    #if os(iOS)
    @Environment(\.horizontalSizeClass) private var sizeClass
    #endif
    let selection: ChatSelection
    let title: String
    let isGroup: Bool
    let readOnlyReason: String?
    @Bindable var model: ConversationModel

    /// Whether the latest message is in view. Known from iOS 18 and macOS 15;
    /// before that it stays true, so new messages always scroll into view and
    /// the jump button never shows.
    @State private var atBottom = true
    @State private var showInfo = false
    /// A decrypted copy being looked at, deleted when the preview closes.
    @State private var previewing: URL?
    @State private var dropTargeted = false
    /// How many people are in a group, once known.
    @State private var memberCount: Int?
    @ScaledMetric(relativeTo: .body) private var jumpSize: CGFloat = 38
    private let bottomID = "bottom"

    var body: some View {
        messages
            #if os(macOS)
            .safeAreaInset(edge: .top, spacing: 0) { floatingHeader }
            #endif
            .safeAreaInset(edge: .bottom, spacing: 0) {
                if let reason = readOnlyReason {
                    Label(reason, systemImage: "lock.fill")
                        .font(.callout)
                        .foregroundStyle(theme.textMuted)
                        .frame(maxWidth: .infinity)
                        .padding(14)
                        .background(theme.surface)
                        .overlay(alignment: .top) { Rectangle().fill(theme.border).frame(height: 1) }
                } else {
                    Composer(model: model)
                }
            }
        .background(ChatBackground())
        .sensoryFeedback(.impact(weight: .light), trigger: model.sent)
        .sensoryFeedback(.error, trigger: model.failed)
        #if os(iOS)
        .navigationTitle(title)
        .navigationBarTitleDisplayMode(.inline)
        .toolbarBackground(theme.surface, for: .navigationBar)
        .toolbarBackground(.visible, for: .navigationBar)
        // A chat is full screen on the iPhone, where the tab bar would sit under the
        // composer; on the iPad the tab bar is how to reach Settings, so it stays.
        .toolbar(sizeClass == .compact ? .hidden : .automatic, for: .tabBar)
        .toolbar {
            ToolbarItem(placement: .principal) { header }.withoutGlass()
            if case .live = selection, readOnlyReason == nil {
                ToolbarItem(placement: .primaryAction) {
                    Button { showInfo = true } label: { Image(systemName: "info.circle") }
                        .accessibilityLabel(isGroup ? "Group info" : "Contact info")
                }
            }
        }
        #endif
        #if os(macOS)
        // On the Mac, info sits beside the chat.
        .inspector(isPresented: $showInfo) {
            // Only while open: a closed inspector's toolbar items otherwise show.
            Group { if showInfo { info } }
                .inspectorColumnWidth(min: 280, ideal: 320, max: 420)
        }
        #else
        .sheet(isPresented: $showInfo) {
            info
                .themedSheet()
                .presentationBackground(theme.bg)
        }
        #endif
        .quickLookPreview($previewing)
        .onChange(of: previewing) { old, new in
            if new == nil, let old { TempFiles.discard(old) }
        }
        // Quick Look is the system's, above any cover: it closes when the app locks.
        .onChange(of: lock.isLocked) { _, locked in
            if locked { previewing = nil }
        }
        #if os(macOS)
        .dropDestination(for: URL.self) { urls, _ in
            guard readOnlyReason == nil, case let .live(id) = selection else { return false }
            for url in urls {
                Task {
                    do { try await app.sendFile(url, to: id) }
                    catch let e as EngineError { app.toast = e.message }
                    catch { app.toast = error.localizedDescription }
                }
            }
            return !urls.isEmpty
        } isTargeted: { dropTargeted = $0 }
        .overlay {
            if dropTargeted {
                RoundedRectangle(cornerRadius: 16).stroke(theme.accent, style: StrokeStyle(lineWidth: 3, dash: [8]))
                    .padding(8)
                    .allowsHitTesting(false)
            }
        }
        #endif
        .task(id: selection) {
            await model.loadLatest()
            if case let .live(id) = selection { app.markRead(id) }
        }
        .task(id: selection) {
            guard isGroup, case .live = selection, let engine = app.engine else { return }
            memberCount = try? await engine.groupMembers(selection.chatID).count
        }
    }

    #if os(macOS)
    /// The chat's header floats over it as a rounded bar: who it is and what
    /// it is, and on the right the chat's info.
    private var floatingHeader: some View {
        HStack(spacing: 10) {
            header
            Spacer(minLength: 8)
            if case .live = selection, readOnlyReason == nil {
                Button { showInfo.toggle() } label: {
                    Image(systemName: "info.circle")
                        .font(.title3)
                        .foregroundStyle(showInfo ? theme.accentText : theme.textMuted)
                        .frame(width: 34, height: 34)
                        .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .accessibilityLabel(isGroup ? "Group info" : "Contact info")
            }
        }
        .padding(.horizontal, 14)
        .frame(height: 50)
        .background(theme.surface, in: RoundedRectangle(cornerRadius: 18, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: 18, style: .continuous).stroke(theme.border))
        .shadow(color: .black.opacity(0.1), radius: 6, y: 1)
        .padding(.horizontal, 6)
        .padding(.top, 6)
        .padding(.bottom, 2)
    }
    #endif

    /// The avatar, the name, and a line under it: how many are in a group, or
    /// that a private chat is end-to-end encrypted. There is no presence in the
    /// protocol, so there is no "online".
    private var header: some View {
        HStack(spacing: 10) {
            Avatar(name: title, isGroup: isGroup, size: 36)
            VStack(alignment: .leading, spacing: 0) {
                Text(title).font(.headline).foregroundStyle(theme.text).lineLimit(1)
                Text(subtitle).font(.caption).foregroundStyle(theme.textMuted).lineLimit(1)
            }
        }
        .accessibilityElement(children: .combine)
        .accessibilityAddTraits(.isHeader)
    }

    private var subtitle: String {
        if case .kept = selection { return String(localized: "Read only") }
        if isGroup {
            if let memberCount { return String(localized: "\(memberCount) members") }
            return String(localized: "Group")
        }
        return String(localized: "end-to-end encrypted")
    }


    private var messages: some View {
        GeometryReader { geo in
            messageScroll(bubbleWidth: min(geo.size.width * 0.7, 640))
        }
    }

    private func messageScroll(bubbleWidth: CGFloat) -> some View {
        ScrollViewReader { proxy in
            ScrollView {
                LazyVStack(spacing: 2) {
                    if model.hasOlder && model.loaded {
                        ProgressView()
                            .padding(8)
                            .onAppear { Task { await model.loadOlder() } }
                    }
                    if let error = model.loadError {
                        Text(error).font(.footnote).foregroundStyle(theme.danger).padding()
                    }
                    ForEach(Array(model.messages.enumerated()), id: \.element.id) { i, m in
                        let prev = i > 0 ? model.messages[i - 1] : nil
                        if prev == nil || !Calendar.current.isDate(prev!.date, inSameDayAs: m.date) {
                            DaySeparator(date: m.date)
                        }
                        let next = i + 1 < model.messages.count ? model.messages[i + 1] : nil
                        MessageRow(message: m, isGroup: isGroup, continues: continues(prev, m),
                                   endsRun: !(next.map { continues(m, $0) } ?? false), maxWidth: bubbleWidth, open: open)
                    }
                    ForEach(model.pending) { p in
                        PendingRow(item: p, model: model)
                    }
                    ForEach(app.transfers.values.filter { $0.chatID == model.chatID }.sorted { $0.id < $1.id }) { t in
                        TransferRow(transfer: t)
                    }
                    // Where the end of the chat is, against the visible area,
                    // says whether the latest message is in view.
                    Color.clear.frame(height: 1).id(bottomID)

                }
                .padding(.horizontal, 12)
                .padding(.vertical, 8)
                .frame(maxWidth: .infinity)
            }
            .modifier(BottomTracker(atBottom: $atBottom))
            .defaultScrollAnchor(.bottom)
            .scrollDismissesKeyboardIfAvailable()
            .onChange(of: model.messages.last?.seq) { old, _ in
                // The first page lands at the end; later messages scroll into
                // view only for someone already there, or for one's own.
                let first = old == nil
                if first || atBottom || model.messages.last?.outgoing == true {
                    Task { @MainActor in
                        await Task.yield() // let the new rows lay out first
                        if first {
                            proxy.scrollTo(bottomID, anchor: .bottom)
                        } else {
                            withAnimation(.easeOut(duration: 0.2)) { proxy.scrollTo(bottomID, anchor: .bottom) }
                        }
                    }
                }
            }
            .onChange(of: model.pending.count) {
                withAnimation(.easeOut(duration: 0.2)) { proxy.scrollTo(bottomID, anchor: .bottom) }
            }
            .overlay(alignment: .bottomTrailing) {
                if !atBottom {
                    Button {
                        withAnimation { proxy.scrollTo(bottomID, anchor: .bottom) }
                    } label: {
                        Image(systemName: "chevron.down")
                            .font(.body.weight(.semibold))
                            .foregroundStyle(theme.text)
                            .frame(width: jumpSize, height: jumpSize)
                            .background(theme.surfaceRaised, in: Circle())
                            .overlay(Circle().stroke(theme.border))
                    }
                    .buttonStyle(.plain)
                    .padding(14)
                    .accessibilityLabel("Jump to the latest message")
                }
            }
        }
    }

    @ViewBuilder private var info: some View {
        if isGroup {
            GroupInfoView(groupID: selection.chatID, name: title)
        } else {
            ContactInfoView(chatID: selection.chatID, name: title)
        }
    }

    /// Opens a kept file: decrypted into a folder of the app's own for Quick
    /// Look, and deleted when the preview closes.
    private func open(_ media: MediaInfo) {
        guard let id = media.mediaID, let engine = app.engine else { return }
        Task {
            do {
                let dir = try TempFiles.folder("viewing")
                previewing = try await engine.exportMedia(account: model.accountID, mediaID: id,
                                                          fileName: media.fileName, dir: dir)
            } catch let e as EngineError {
                app.toast = e.message
            } catch {}
        }
    }

    /// A message continues the run before it: same sender, same day, close in time.
    private func continues(_ prev: ChatMessage?, _ m: ChatMessage) -> Bool {
        guard let prev, !prev.isSystem, !m.isSystem, prev.outgoing == m.outgoing, prev.sender == m.sender else { return false }
        return m.date.timeIntervalSince(prev.date) < 120 && Calendar.current.isDate(prev.date, inSameDayAs: m.date)
    }
}

private extension View {
    func cappedWidth(_ maxWidth: CGFloat) -> some View { CappedWidth(maxWidth: maxWidth) { self } }
}

private extension ToolbarContent {
    /// The system draws a toolbar item on a glass pill from iOS and macOS 26;
    /// the chat's header sits on the bar itself.
    @ToolbarContentBuilder func withoutGlass() -> some ToolbarContent {
        if #available(macOS 26, iOS 26, *) {
            self.sharedBackgroundVisibility(.hidden)
        } else {
            self
        }
    }
}

/// Offers its content at most `maxWidth`, and takes the size the content
/// chooses: a bubble hugs its text up to the cap. `frame(maxWidth:)` would
/// stretch it to the cap instead.
private struct CappedWidth: Layout {
    var maxWidth: CGFloat

    func sizeThatFits(proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) -> CGSize {
        guard let view = subviews.first else { return .zero }
        return view.sizeThatFits(ProposedViewSize(width: min(proposal.width ?? maxWidth, maxWidth), height: proposal.height))
    }

    func placeSubviews(in bounds: CGRect, proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) {
        subviews.first?.place(at: bounds.origin, anchor: .topLeading,
                              proposal: ProposedViewSize(width: bounds.width, height: bounds.height))
    }
}

/// Reports whether a scroll view is at its end.
private struct BottomTracker: ViewModifier {
    @Binding var atBottom: Bool

    func body(content: Content) -> some View {
        if #available(iOS 18, macOS 15, *) {
            content.onScrollGeometryChange(for: Bool.self) { g in
                g.visibleRect.maxY >= g.contentSize.height + g.contentInsets.bottom - 24
            } action: { _, now in
                atBottom = now
            }
        } else {
            content
        }
    }
}

struct DaySeparator: View {
    @Environment(\.theme) private var theme
    let date: Date

    var body: some View {
        Text(ChatFormat.day(date))
            .font(.callout.weight(.medium))
            .foregroundStyle(theme.text)
            .padding(.vertical, 12)
            .frame(maxWidth: .infinity)
            .accessibilityAddTraits(.isHeader)
    }
}

struct MessageRow: View {
    @Environment(\.theme) private var theme
    let message: ChatMessage
    let isGroup: Bool
    let continues: Bool
    /// The last of a run from one sender: its corner on the sender's side is the
    /// small one.
    let endsRun: Bool
    /// The widest a bubble may be.
    let maxWidth: CGFloat
    let open: (MediaInfo) -> Void
    @State private var showInfo = false

    var body: some View {
        if message.isSystem {
            Text(message.text ?? "")
                .font(.footnote)
                .multilineTextAlignment(.center)
                .foregroundStyle(theme.textMuted)
                .padding(.horizontal, 24)
                .padding(.vertical, 8)
                .frame(maxWidth: .infinity)
        } else {
            HStack(alignment: .bottom) {
                if message.outgoing { Spacer(minLength: 48) }
                bubble
                if !message.outgoing { Spacer(minLength: 48) }
            }
            .padding(.top, continues ? 1 : 6)
        }
    }

    private var tick: TickState { TickState(message) }

    /// The time and, on your own messages, the ticks. Smaller, not fainter: the
    /// theme's meta colours are held to 4.5:1 on the bubble.
    private func meta(out: Bool) -> some View {
        HStack(spacing: 4) {
            Text(ChatFormat.time(message.date))
            if out {
                TickView(state: tick, delivered: message.deliveredCount, readBy: message.readCount,
                         total: message.total)
            }
        }
        .font(.caption2)
        .foregroundStyle(out ? theme.metaOut : theme.metaIn)
    }

    private var bubble: some View {
        let out = message.outgoing
        return VStack(alignment: .leading, spacing: 3) {
            if isGroup && !out && !continues, let name = message.senderName {
                Text(name)
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(theme.nameColor(for: message.sender ?? name))
            }
            if let media = message.media {
                MediaBubbleContent(media: media, outgoing: out) { open(media) }
            }
            if let text = message.text, !text.isEmpty {
                Text(text)
                    .font(.body)
                    .foregroundStyle(out ? theme.onBubbleOut : theme.onBubbleIn)
                    .textSelection(.enabled)
                    .fixedSize(horizontal: false, vertical: true)
            }
            // Laid out invisibly to give the bubble its room, drawn in the corner
            // over it, so a short message hugs its text and the time stays at the edge.
            meta(out: out).hidden()
        }
        .overlay(alignment: .bottomTrailing) { meta(out: out) }
        .cappedWidth(maxWidth - 24)
        .padding(.horizontal, 12)
        .padding(.vertical, 7)
        .background(out ? theme.bubbleOut : theme.bubbleIn, in: Self.shape(outgoing: out, tail: endsRun))
        .shadow(color: .black.opacity(0.06), radius: 0.5, y: 0.5)
        .contextMenu {
            if let text = message.text, !text.isEmpty {
                Button("Copy", systemImage: "doc.on.doc") { Clipboard.copy(text) }
            }
            if out, isGroup, (message.total ?? 0) > 1 {
                Button("Message info", systemImage: "info.circle") { showInfo = true }
            }
        }
        .alert("Message info", isPresented: $showInfo) {
            Button("OK", role: .cancel) {}
        } message: {
            Text(info)
        }
        // One element for VoiceOver, read as who, what, when and whether it went.
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(spoken)
        .accessibilityActions {
            if let media = message.media, media.mediaID != nil {
                Button("Open \(media.fileName)") { open(media) }
            }
            if out, isGroup, (message.total ?? 0) > 1 {
                Button("Message info") { showInfo = true }
            }
        }
    }

    /// Rounded all round, but a small corner where the sender's side meets the
    /// bottom, on the last bubble of a run.
    private static func shape(outgoing: Bool, tail: Bool) -> UnevenRoundedRectangle {
        let big: CGFloat = 18, small: CGFloat = tail ? 5 : 18
        return UnevenRoundedRectangle(topLeadingRadius: big, bottomLeadingRadius: outgoing ? big : small,
                                      bottomTrailingRadius: outgoing ? small : big, topTrailingRadius: big,
                                      style: .continuous)
    }

    private var info: String {
        let total = message.total ?? 0
        return String(localized: "Delivered to \(message.deliveredCount ?? 0) of \(total)\nRead by \(message.readCount ?? 0) of \(total)")
    }

    private var spoken: String {
        var parts = [message.outgoing ? "You" : (message.senderName ?? "")]
        if let media = message.media {
            parts.append("\(media.thumbnail != nil ? "Photo" : "File") \(media.fileName)")
        }
        parts.append(message.text ?? "")
        parts.append(ChatFormat.time(message.date))
        if message.outgoing {
            parts.append(tick.spoken(delivered: message.deliveredCount, read: message.readCount, total: message.total))
        }
        return parts.filter { !$0.isEmpty }.joined(separator: ", ")
    }
}

/// A message on its way out, or one that could not go.
struct PendingRow: View {
    @Environment(\.theme) private var theme
    let item: PendingMessage
    let model: ConversationModel

    var body: some View {
        VStack(alignment: .trailing, spacing: 4) {
            HStack {
                Spacer(minLength: 48)
                VStack(alignment: .trailing, spacing: 3) {
                    Text(item.text)
                        .foregroundStyle(theme.onBubbleOut)
                        .fixedSize(horizontal: false, vertical: true)
                    if item.error == nil {
                        HStack(spacing: 4) {
                            Text("Sending")
                            TickView(state: .clock)
                        }
                        .font(.caption2)
                        .foregroundStyle(theme.metaOut)
                    }
                }
                .padding(.horizontal, 12)
                .padding(.vertical, 7)
                // Full strength, so its text keeps its contrast; the label below
                // says how it stands.
                .background(theme.bubbleOut, in: UnevenRoundedRectangle(
                    topLeadingRadius: 18, bottomLeadingRadius: 18, bottomTrailingRadius: 5, topTrailingRadius: 18,
                    style: .continuous))
            }
            if let error = item.error {
                HStack(spacing: 12) {
                    Label(error, systemImage: "exclamationmark.circle.fill")
                        .foregroundStyle(theme.danger)
                    Button("Retry") { Task { await model.retry(item) } }
                        .foregroundStyle(theme.accentText)
                    Button("Delete") { model.discard(item) }
                        .foregroundStyle(theme.textMuted)
                }
                .font(.caption)
                .buttonStyle(.plain)
            }
        }
        .padding(.top, 6)
    }
}

/// The message box. On the Mac, Return sends and Shift-Return starts a new line;
/// on the iPhone, the send button sends.
struct Composer: View {
    @Environment(AppState.self) private var app
    @Environment(\.theme) private var theme
    @Bindable var model: ConversationModel
    @ScaledMetric(relativeTo: .body) private var buttonSize: CGFloat = 40
    @FocusState private var focused: Bool

    var body: some View {
        HStack(alignment: .bottom, spacing: 8) {
            AttachButton(chatID: model.chatID)
                .background(theme.surface, in: Circle())
                .overlay(Circle().stroke(theme.border.opacity(0.6)))

            // The pill floats over the chat: the message, and on the Mac the
            // emoji picker.
            HStack(alignment: .bottom, spacing: 0) {
                // The draft lives on the chat's model, so it is still there after
                // switching chats and back, for as long as the app runs.
                TextField("", text: $model.draft, prompt: Text("Write a message…").foregroundStyle(theme.textMuted), axis: .vertical)
                    .textFieldStyle(.plain)
                    .lineLimit(1...6)
                    .foregroundStyle(theme.text)
                    .focused($focused)
                    .accessibilityLabel("Message")
                    .padding(.vertical, 10)
                    .padding(.horizontal, 12)
                    #if os(macOS)
                    .onKeyPress(.return, phases: .down) { press in
                        if press.modifiers.contains(.shift) { return .ignored }
                        send()
                        return .handled
                    }
                    #endif
                #if os(macOS)
                // The system's emoji picker types into the focused field. On the
                // iPhone it is the keyboard's own, which an app cannot open.
                Button {
                    focused = true
                    NSApp.orderFrontCharacterPalette(nil)
                } label: {
                    Image(systemName: "face.smiling")
                        .font(.body.weight(.semibold))
                        .foregroundStyle(theme.textMuted)
                        .frame(width: buttonSize, height: buttonSize)
                }
                .buttonStyle(.plain)
                .accessibilityLabel("Emoji")
                #endif
            }
            .padding(.horizontal, 4)
            .background(theme.surface, in: RoundedRectangle(cornerRadius: 22, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: 22, style: .continuous).stroke(theme.border.opacity(0.6)))

            Button(action: send) {
                Image(systemName: "arrow.up")
                    .font(.body.weight(.bold))
                    .foregroundStyle(canSend ? theme.onAccent : theme.textMuted)
                    .frame(width: buttonSize + 4, height: buttonSize + 4)
                    .background(canSend ? theme.accent : theme.surface, in: Circle())
                    .overlay(Circle().stroke(theme.border.opacity(canSend ? 0 : 0.6)))
            }
            .buttonStyle(.plain)
            .disabled(!canSend)
            .accessibilityLabel("Send")
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
        .overlay(alignment: .top) {
            if app.connection != .online {
                Text(app.connection == .connecting ? "Connecting… messages send once you're back online."
                                                   : "You're offline. Messages can't be sent.")
                    .font(.caption)
                    .foregroundStyle(theme.textMuted)
                    .padding(.horizontal, 10)
                    .padding(.vertical, 4)
                    .background(theme.surfaceRaised, in: Capsule())
                    .offset(y: -24)
            }
        }
    }

    private var canSend: Bool { !model.draft.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty }

    private func send() {
        guard canSend else { return }
        let body = model.draft
        model.draft = ""
        Task { await model.send(body) }
    }
}

enum Clipboard {
    static func copy(_ text: String) {
        #if os(macOS)
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
        #else
        UIPasteboard.general.string = text
        #endif
    }
}
