import SwiftUI

/// Picks the screen for the app's phase, and draws everything in the chosen
/// theme.
struct RootView: View {
    @Environment(AppState.self) private var app
    @Environment(AppLock.self) private var lock
    @Environment(\.theme) private var theme

    var body: some View {
        Group {
            switch app.phase {
            case .launching:
                VStack(spacing: 16) {
                    MeshMark(size: 64)
                    ProgressView().tint(theme.accentText)
                }
            case let .failed(message):
                VStack(spacing: 14) {
                    Image(systemName: "exclamationmark.lock.fill").font(.largeTitle).foregroundStyle(theme.danger)
                        .accessibilityHidden(true)
                    Text("GoMesh can't start").font(.title2.weight(.bold)).foregroundStyle(theme.text)
                    Text(message).multilineTextAlignment(.center).foregroundStyle(theme.textMuted)
                }
                .padding(32)
            case .welcome:
                WelcomeView()
            case let .auth(mode):
                AuthView(mode: mode).id(mode == .create ? "create" : "signIn")
            case .signedIn:
                HomeView()
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(theme.bg.ignoresSafeArea())
        .overlay(alignment: .bottom) { toast }
        .overlay {
            if lock.isLocked {
                LockScreen()
            } else if lock.isCovered {
                LockCover()
            }
        }
        .animation(.easeInOut(duration: 0.2), value: app.phase)
        .sensoryFeedback(.success, trigger: lock.unlocks)
    }

    @ViewBuilder private var toast: some View {
        if let text = app.toast {
            Text(text)
                .font(.callout)
                .foregroundStyle(theme.text)
                .padding(.horizontal, 16)
                .padding(.vertical, 10)
                .background(theme.surfaceRaised, in: Capsule())
                .overlay(Capsule().stroke(theme.border))
                .padding(.bottom, 24)
                .onTapGesture { app.toast = nil }
                .task(id: text) {
                    try? await Task.sleep(for: .seconds(4))
                    if app.toast == text { app.toast = nil }
                }
        }
    }
}

/// Resolves the chosen theme against the system's light or dark mode and
/// hands it down.
///
/// The main window fixes the system controls' scheme with preferredColorScheme,
/// nil under Auto. A sheet must never be handed nil: a presentation that once
/// had a scheme forced keeps it when given nil, so Auto would stay stuck on the
/// last theme's scheme. A sheet therefore takes the theme its presenter already
/// resolved and always forces that theme's scheme. Another window, such as the
/// Mac's Settings, resolves for itself and themes only its content.
struct Themed: ViewModifier {
    enum Kind { case root, sheet, window }
    let kind: Kind
    @Environment(ThemeStore.self) private var store
    @Environment(AppLock.self) private var lock: AppLock?
    @Environment(\.colorScheme) private var scheme
    @Environment(\.theme) private var inherited

    func body(content: Content) -> some View {
        switch kind {
        case .root:
            let theme = store.resolved(for: scheme)
            content
                .environment(\.theme, theme)
                .tint(theme.accentText)
                .preferredColorScheme(store.preferredScheme)
        case .sheet:
            content
                .environment(\.theme, inherited)
                .tint(inherited.accentText)
                .preferredColorScheme(inherited.colorScheme)
                .overlay { cover.environment(\.theme, inherited) }
        case .window:
            let theme = store.resolved(for: scheme)
            content
                .environment(\.theme, theme)
                .environment(\.colorScheme, theme.colorScheme)
                .tint(theme.accentText)
                .overlay { cover.environment(\.theme, theme) }
        }
    }

    /// A sheet or another window shows nothing while the app is locked or out
    /// of sight; the main window has the lock screen.
    @ViewBuilder private var cover: some View {
        if let lock, lock.isLocked || lock.isCovered {
            LockCover()
        }
    }
}

extension View {
    /// For the main window's root.
    func themed() -> some View { modifier(Themed(kind: .root)) }
    /// For a sheet's content.
    func themedSheet() -> some View { modifier(Themed(kind: .sheet)) }
    /// For a window other than the main one.
    func themedWindow() -> some View { modifier(Themed(kind: .window)) }
}
