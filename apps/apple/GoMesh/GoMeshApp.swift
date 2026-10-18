import SwiftUI

@main
struct GoMeshApp: App {
    @State private var app = AppState()
    @State private var themes = ThemeStore()
    @State private var lock = AppLock()
    @Environment(\.scenePhase) private var scenePhase

    var body: some Scene {
        WindowGroup {
            RootView()
                .themed()
                .environment(app)
                .environment(themes)
                .environment(lock)
                .task {
                    #if DEBUG
                    if AutoTest.requested {
                        await AutoTest.run(app: app, themes: themes)
                        return
                    }
                    #endif
                    await app.launch()
                }
                #if os(macOS)
                .frame(minWidth: 720, minHeight: 520)
                #endif
        }
        .onChange(of: scenePhase) { _, phase in
            lock.sceneChanged(phase)
            app.scenePhaseChanged(phase)
        }
        .commands {
            CommandGroup(replacing: .newItem) {
                Button("New Chat") { app.command = .newChat }
                    .keyboardShortcut("n")
                    .disabled(app.phase != .signedIn)
                Button("New Group") { app.command = .newGroup }
                    .keyboardShortcut("n", modifiers: [.command, .shift])
                    .disabled(app.phase != .signedIn)
            }
            CommandGroup(after: .textEditing) {
                Button("Search Chats") { app.command = .search }
                    .keyboardShortcut("k")
                    .disabled(app.phase != .signedIn)
            }
        }

        #if os(macOS)
        Settings {
            SettingsView()
                .themedWindow()
                .environment(app)
                .environment(themes)
                .environment(lock)
                .frame(width: 480, height: 560)
        }
        #endif
    }
}
