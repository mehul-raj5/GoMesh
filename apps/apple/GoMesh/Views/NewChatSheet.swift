import SwiftUI

/// Start a private chat by username. A chat that exists is opened as it is;
/// nothing here starts one over.
struct NewChatSheet: View {
    @Environment(AppState.self) private var app
    @Environment(\.theme) private var theme
    @Environment(\.dismiss) private var dismiss
    let opened: (String) -> Void
    @State private var username = ""
    @State private var busy = false
    @State private var error: String?

    var body: some View {
        NavigationStack {
            VStack(alignment: .leading, spacing: 16) {
                FormField(label: "Username", text: $username, error: error, contentType: .username)
                    .onSubmit(start)
                Button(action: start) {
                    HStack(spacing: 8) {
                        if busy { ProgressView().controlSize(.small).tint(theme.onAccent) }
                        Text("Start chat")
                    }
                }
                .buttonStyle(AccentButtonStyle())
                .disabled(busy || username.trimmingCharacters(in: .whitespaces).isEmpty)
                Spacer()
            }
            .padding(24)
            .background(theme.bg)
            .navigationTitle("New chat")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } }
            }
            .onChange(of: username) { error = nil }
        }
    }

    private func start() {
        let name = username.trimmingCharacters(in: .whitespaces)
        guard !name.isEmpty, !busy else { return }
        if let existing = app.chats.first(where: { !$0.isGroup && !$0.readOnly && $0.name.caseInsensitiveCompare(name) == .orderedSame }) {
            dismiss()
            opened(existing.id)
            return
        }
        busy = true
        Task {
            defer { busy = false }
            do {
                let id = try await app.openDirect(name)
                dismiss()
                opened(id)
            } catch let e as EngineError {
                error = e.message
            } catch {}
        }
    }
}

/// A private chat's person: the safety number to compare, and the way to start
/// the chat's secure session over.
struct ContactInfoView: View {
    @Environment(AppState.self) private var app
    @Environment(\.theme) private var theme
    @Environment(\.dismiss) private var dismiss
    let chatID: String
    let name: String
    @State private var safety: String?
    @State private var error: String?
    @State private var confirmRestart = false

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 20) {
                    Avatar(name: name, size: 84)
                    Text(name).font(.title2.weight(.bold)).foregroundStyle(theme.text)
                    VStack(alignment: .leading, spacing: 10) {
                        Text("Safety number").font(.headline).foregroundStyle(theme.text)
                        Text("Compare this with \(name), in person or over a call. If it matches on both devices, nobody is in the middle.")
                            .font(.callout).foregroundStyle(theme.textMuted)
                            .fixedSize(horizontal: false, vertical: true)
                        if let safety {
                            Text(safety)
                                .font(.system(.title3, design: .monospaced))
                                .foregroundStyle(theme.text)
                                .textSelection(.enabled)
                                .lineLimit(nil)
                                .fixedSize(horizontal: false, vertical: true)
                                .padding(14)
                                .frame(maxWidth: .infinity, alignment: .leading)
                                .background(theme.surfaceRaised, in: RoundedRectangle(cornerRadius: 12))
                        } else if let error {
                            Text(error).font(.callout).foregroundStyle(theme.danger)
                        } else {
                            ProgressView()
                        }
                    }
                    VStack(alignment: .leading, spacing: 8) {
                        Button("Start a fresh secure session…", role: .destructive) { confirmRestart = true }
                            .buttonStyle(.plain)
                            .foregroundStyle(theme.danger)
                        Text("Only if messages from \(name) stopped arriving or can't be read.")
                            .font(.footnote).foregroundStyle(theme.textMuted)
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
                .padding(24)
            }
            .background(theme.bg)
            .navigationTitle("Contact info")
            .toolbar {
                ToolbarItem(placement: .confirmationAction) { Button("Done") { dismiss() } }
            }
            .confirmationDialog("Start a fresh secure session with \(name)?", isPresented: $confirmRestart,
                                titleVisibility: .visible) {
                Button("Start over", role: .destructive) {
                    Task {
                        do { try await app.engine?.restartChat(chatID); dismiss() }
                        catch let e as EngineError { error = e.message }
                        catch {}
                    }
                }
            } message: {
                Text("Messages either of you sent on the old session may not arrive.")
            }
            .task {
                do { safety = try await app.engine?.safetyNumber(chatID) }
                catch let e as EngineError { error = e.message }
                catch {}
            }
        }
    }
}
