import SwiftUI

struct SettingsView: View {
    @Environment(AppState.self) private var app
    @Environment(ThemeStore.self) private var themes
    @Environment(AppLock.self) private var lock
    @Environment(\.theme) private var theme
    @Environment(\.dismiss) private var dismiss
    var inSheet = false
    @State private var confirmSignOut = false
    @State private var confirmDeleteAll = false
    @AppStorage(Notifier.previewsKey) private var showPreviews = false
    @State private var deleteHistory = false
    @State private var lockProblem: String?

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    NavigationLink {
                        AppearancePicker()
                    } label: {
                        LabeledContent("Appearance") {
                            Text(currentThemeName).foregroundStyle(theme.textMuted)
                        }
                    }
                }
                .listRowBackground(theme.surface)

                Section {
                    Toggle("Show sender and message in notifications", isOn: $showPreviews)
                } header: {
                    Text("Notifications")
                } footer: {
                    Text("Notifications are kept by the system, outside GoMesh's encryption. Off, they say only \"New message\".")
                        .foregroundStyle(theme.textMuted)
                }
                .listRowBackground(theme.surface)

                privacy
                    .listRowBackground(theme.surface)

                appLock
                    .listRowBackground(theme.surface)

                if let account = app.account {
                    Section("Account") {
                        LabeledContent("Username", value: account.username)
                        LabeledContent("Server", value: app.server)
                        Toggle("Also delete this account's chats from this device", isOn: $deleteHistory)
                        Button("Sign out", role: .destructive) { confirmSignOut = true }
                            .foregroundStyle(theme.danger)
                        Button("Delete all data and sign out", role: .destructive) { confirmDeleteAll = true }
                            .foregroundStyle(theme.danger)
                    }
                    .listRowBackground(theme.surface)
                }

                Section("This device") {
                    LabeledContent("Keys", value: app.vaultDescription)
                }
                .listRowBackground(theme.surface)
            }
            .formStyle(.grouped)
            .scrollContentBackground(.hidden)
            .background(theme.bg)
            .foregroundStyle(theme.text)
            .navigationTitle("Settings")
            .toolbarBackground(theme.surface, for: .automatic)
            .toolbar {
                if inSheet {
                    ToolbarItem(placement: .confirmationAction) {
                        Button("Done") { dismiss() }
                    }
                }
            }
            .confirmationDialog("Sign out of GoMesh?", isPresented: $confirmSignOut, titleVisibility: .visible) {
                Button(deleteHistory ? "Sign out and delete chats" : "Sign out", role: .destructive) {
                    dismiss()
                    Task { await app.signOut(deleteHistory: deleteHistory) }
                }
            } message: {
                Text(deleteHistory
                     ? "This device's keys and this account's chats will be deleted."
                     : "This device's keys will be deleted. Its chats stay readable here, but nobody can send from them.")
            }
            .confirmationDialog("Delete all data?", isPresented: $confirmDeleteAll, titleVisibility: .visible) {
                Button("Delete all data and sign out", role: .destructive) {
                    dismiss()
                    Task { await app.deleteAllData() }
                }
            } message: {
                Text("Every account's chats and files on this device, and all keys, will be deleted, and you will be signed out. GoMesh starts over as if just installed. This can't be undone.")
            }
        }
        .tint(theme.accentText)
    }

    @ViewBuilder private var privacy: some View {
        @Bindable var app = app
        Section {
            Toggle("Send read receipts", isOn: $app.sendReadReceipts)
        } header: {
            Text("Privacy")
        } footer: {
            Text("When off, people won't see when you've read their messages, and you won't be told when they read yours.")
                .foregroundStyle(theme.textMuted)
        }
    }

    @ViewBuilder private var appLock: some View {
        @Bindable var lock = lock
        Section {
            Toggle("Require \(AppLock.methodName)", isOn: Binding(
                get: { lock.enabled },
                set: { on in
                    Task {
                        let why = await lock.setEnabled(on)
                        lockProblem = (why?.isEmpty ?? true) ? nil : why
                    }
                }))
            if lock.enabled {
                Picker("Lock", selection: $lock.delay) {
                    ForEach(AppLock.Delay.allCases) { Text($0.label).tag($0) }
                }
            }
        } header: {
            Text("App Lock")
        } footer: {
            if let lockProblem {
                Text(lockProblem).foregroundStyle(theme.danger)
            } else {
                Text("Asks for \(AppLock.methodName) when GoMesh opens or comes back, and hides your chats in the app switcher.")
                    .foregroundStyle(theme.textMuted)
            }
        }
    }

    private var currentThemeName: String {
        themes.isAuto ? "Auto" : (Theme.named(themes.selection)?.name ?? "Auto")
    }
}
