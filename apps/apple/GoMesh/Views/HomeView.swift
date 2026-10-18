import SwiftUI

/// The signed-in app. On the iPhone, Chats and Settings tabs; on the Mac, chats
/// on the side, the chat in the detail, and Settings in its own window.
struct HomeView: View {
    @Environment(\.theme) private var theme

    var body: some View {
        #if os(iOS)
        TabView {
            ChatsHome()
                .tabItem { Label("Chats", systemImage: "bubble.left.and.bubble.right.fill") }
            SettingsView()
                .tabItem { Label("Settings", systemImage: "gearshape.fill") }
        }
        .tint(theme.accentText)
        #else
        ChatsHome()
        #endif
    }
}

struct ChatsHome: View {
    @Environment(AppState.self) private var app
    @Environment(\.theme) private var theme
    @State private var selection: ChatSelection?
    @State private var search = ""
    @State private var showSettings = false
    @State private var showNewChat = false
    @State private var showNewGroup = false
    @FocusState private var searchFocused: Bool

    var body: some View {
        layout
        .tint(theme.accentText)
        .onChange(of: selection) {
            // Only a live chat counts as on screen for reading and notifications.
            if case let .live(id) = selection { app.selectedChat = id } else { app.selectedChat = nil }
        }
        .onChange(of: app.requestedChat) {
            if let id = app.requestedChat {
                selection = .live(id)
                app.requestedChat = nil
            }
        }
        .onChange(of: app.command) {
            switch app.command {
            case .newChat: showNewChat = true
            case .newGroup: showNewGroup = true
            case .search: searchFocused = true
            case nil: break
            }
            app.command = nil
        }
        .sheet(isPresented: $showSettings) {
            SettingsView(inSheet: true)
                .themedSheet() // a sheet is its own presentation: give it the scheme too
                .presentationBackground(theme.bg)
                #if os(macOS)
                .frame(minWidth: 480, minHeight: 560)
                #endif
        }
        .sheet(isPresented: $showNewGroup) {
            NewGroupSheet { id in selection = .live(id) }
                .themedSheet()
                .presentationBackground(theme.bg)
                #if os(macOS)
                .frame(minWidth: 420, minHeight: 460)
                #endif
        }
        .sheet(isPresented: $showNewChat) {
            NewChatSheet { id in selection = .live(id) }
                .themedSheet()
                .presentationBackground(theme.bg)
                .presentationDetents([.medium])
                #if os(macOS)
                .frame(minWidth: 380, minHeight: 240)
                #endif
        }
    }

    @ViewBuilder private var layout: some View {
        #if os(macOS)
        // The sidebar floats as a rounded panel over the chat's ground, with the
        // window's own buttons inside it.
        HStack(spacing: 0) {
            sidebarPanel
            detail
        }
        .background(theme.chatBg.ignoresSafeArea())
        #else
        NavigationSplitView {
            VStack(spacing: 0) {
                header
                if app.connection != .online { connectionBar }
                ChatListView(selection: $selection, search: $search)
            }
            .background(theme.surface)
            .navigationTitle("Chats")
            .toolbar(.hidden, for: .navigationBar)
        } detail: {
            detail
        }
        #endif
    }

    #if os(macOS)
    private var sidebarPanel: some View {
        VStack(spacing: 0) {
            // The traffic lights sit at the left; the title stays centred.
            ZStack {
                Text("Chats").font(.headline).foregroundStyle(theme.text)
                HStack {
                    Spacer()
                    Menu {
                        Button("New chat", systemImage: "person") { showNewChat = true }
                        Button("New group", systemImage: "person.3") { showNewGroup = true }
                    } label: {
                        Image(systemName: "square.and.pencil")
                            .font(.title3)
                            .foregroundStyle(theme.accentText)
                            .frame(width: 32, height: 32)
                            .contentShape(Rectangle())
                    }
                    .menuStyle(.button)
                    .buttonStyle(.plain)
                    .menuIndicator(.hidden)
                    .fixedSize()
                    .disabled(app.connection != .online)
                    .accessibilityLabel("New chat or group")
                }
            }
            .padding(.horizontal, 14)
            .frame(height: 44)

            searchPill
                .padding(.horizontal, 10)
                .padding(.bottom, 8)
            if app.connection != .online { connectionBar }
            ChatListView(selection: $selection, search: $search)
            tabBar
        }
        .frame(width: 310)
        .background(theme.surface, in: RoundedRectangle(cornerRadius: 22, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: 22, style: .continuous).stroke(theme.border))
        .shadow(color: .black.opacity(0.12), radius: 8, y: 2)
        .padding(.leading, 6)
        .padding(.vertical, 6)
        .padding(.trailing, 4)
    }

    /// What there is to switch between: the chats, who you are signed in as,
    /// and Settings. There is no calls or contacts screen to point at.
    private var tabBar: some View {
        let unread = app.chats.reduce(Int64(0)) { $0 + $1.unread }
        return HStack {
            Menu {
                if let name = app.account?.username {
                    Label(name, systemImage: "person.crop.circle").disabled(true)
                }
            } label: {
                Image(systemName: "person.crop.circle.fill").font(.title2)
                    .foregroundStyle(theme.textMuted).frame(width: 44, height: 40).contentShape(Rectangle())
            }
            .menuStyle(.button)
            .buttonStyle(.plain)
            .menuIndicator(.hidden)
            .fixedSize()
            .accessibilityLabel("Account")
            Spacer()
            Image(systemName: "bubble.left.and.bubble.right.fill").font(.title2)
                .foregroundStyle(theme.accentText).frame(width: 44, height: 40)
                .overlay(alignment: .topTrailing) {
                    if unread > 0 {
                        Text(unread > 99 ? "99+" : "\(unread)")
                            .font(.caption2.weight(.bold))
                            .foregroundStyle(theme.bg)
                            .padding(.horizontal, 5)
                            .frame(minWidth: 18, minHeight: 18)
                            .background(theme.danger, in: Capsule())
                            .offset(x: 6, y: -2)
                    }
                }
                .accessibilityElement(children: .ignore)
                .accessibilityLabel("Chats, \(unread) unread")
            Spacer()
            Button { showSettings = true } label: {
                Image(systemName: "gearshape.fill").font(.title2)
                    .foregroundStyle(theme.textMuted).frame(width: 44, height: 40).contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .accessibilityLabel("Settings")
        }
        .padding(.horizontal, 22)
        .padding(.vertical, 6)
        .overlay(alignment: .top) { Rectangle().fill(theme.border.opacity(0.5)).frame(height: 1) }
    }
    #endif

    /// The menu and the search pill that head the sidebar.
    private var header: some View {
        HStack(spacing: 8) {
            Menu {
                if let name = app.account?.username {
                    Label(name, systemImage: "person.crop.circle").disabled(true)
                    Divider()
                }
                Button("New chat", systemImage: "person") { showNewChat = true }
                    .disabled(app.connection != .online)
                Button("New group", systemImage: "person.3") { showNewGroup = true }
                    .disabled(app.connection != .online)
                #if os(macOS)
                Divider()
                Button("Settings", systemImage: "gearshape") { showSettings = true }
                #endif
            } label: {
                Image(systemName: "line.3.horizontal")
                    .font(.title3.weight(.medium))
                    .foregroundStyle(theme.textMuted)
                    .frame(width: 40, height: 40)
                    .contentShape(Rectangle())
            }
            .menuStyle(.button)
            .buttonStyle(.plain)
            .menuIndicator(.hidden)
            .fixedSize()
            .accessibilityLabel("Menu")

            searchPill
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 8)
    }

    #if os(macOS)
    private static let searchPrompt = "Search (⌘K)"
    #else
    private static let searchPrompt = "Search"
    #endif

    private var searchPill: some View {
        HStack(spacing: 8) {
            Image(systemName: "magnifyingglass").foregroundStyle(theme.textMuted).accessibilityHidden(true)
            TextField("", text: $search, prompt: Text(Self.searchPrompt).foregroundStyle(theme.textMuted))
                .textFieldStyle(.plain)
                .foregroundStyle(theme.text)
                .focused($searchFocused)
                .autocorrectionDisabled()
                .accessibilityLabel("Search chats")
            if !search.isEmpty {
                Button { search = "" } label: {
                    Image(systemName: "xmark.circle.fill").foregroundStyle(theme.textMuted)
                }
                .buttonStyle(.plain)
                .accessibilityLabel("Clear search")
            }
        }
        .padding(.horizontal, 12)
        .frame(minHeight: 36)
        .background(theme.surfaceRaised.opacity(0.6), in: Capsule())
        .overlay(Capsule().stroke(theme.border.opacity(0.7)))
    }

    /// Shown only when not online; online is the ordinary state.
    private var connectionBar: some View {
        HStack(spacing: 8) {
            ConnectionPill(connection: app.connection)
            if !app.connectionText.isEmpty {
                Text(app.connectionText).font(.caption2).foregroundStyle(theme.textMuted).lineLimit(2)
            }
            Spacer(minLength: 0)
        }
        .padding(.horizontal, 14)
        .padding(.bottom, 8)
    }

    @ViewBuilder private var detail: some View {
        switch selection {
        case let .live(id):
            if let chat = app.chats.first(where: { $0.id == id }) {
                ConversationView(selection: .live(id), title: chat.name, isGroup: chat.isGroup,
                                 readOnlyReason: chat.readOnly ? String(localized: "You're no longer in this chat.") : nil,
                                 model: app.model(for: id, readOnly: chat.readOnly))
                    .id(id)
            } else {
                placeholder
            }
        case let .kept(account, chatID):
            if let group = app.earlier.first(where: { $0.account.id == account }),
               let chat = group.chats.first(where: { $0.id == chatID }) {
                ConversationView(selection: .kept(account: account, chat: chatID), title: chat.name, isGroup: chat.isGroup,
                                 readOnlyReason: String(localized: "This chat belongs to \(group.account.username)."),
                                 model: app.model(for: chatID, account: account, readOnly: true))
                    .id(account + chatID)
            } else {
                placeholder
            }
        case nil:
            placeholder
        }
    }

    private var placeholder: some View {
        VStack(spacing: 12) {
            MeshMark(size: 64)
            Text("Select a chat to start messaging").font(.callout.weight(.medium)).foregroundStyle(theme.text)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(theme.chatBg)
    }
}
