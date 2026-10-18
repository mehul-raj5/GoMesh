import SwiftUI

/// Create an account, or sign in to one. The server's certificate is
/// checked first; one this device has never seen is shown for the person to
/// compare before any password is sent to it.
struct AuthView: View {
    @Environment(AppState.self) private var app
    @Environment(\.theme) private var theme
    let mode: AppState.AuthMode

    @State private var username = ""
    @State private var password = ""
    @State private var confirm = ""
    @State private var server = ""
    @State private var showAdvanced = false
    @State private var busy = false
    @State private var errors = FieldErrors()
    @State private var pendingTrust: ServerCheck?
    /// The server presented a certificate other than the pinned one.
    @State private var certificateChanged = false
    @State private var confirmForget = false

    struct FieldErrors: Equatable {
        var username: String?
        var password: String?
        var confirm: String?
        var server: String?
        var general: String?
    }

    private var isCreate: Bool { mode == .create }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                header
                if let notice = app.authNotice {
                    Label(notice, systemImage: "info.circle.fill")
                        .font(.callout)
                        .foregroundStyle(theme.text)
                        .padding(12)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .background(theme.warning.opacity(0.15), in: RoundedRectangle(cornerRadius: 10))
                }
                // Creating an account marks no field for AutoFill. A username box and two
                // password boxes are enough for iOS to offer a strong password of its own,
                // which covers the boxes and, with no associated domain for a self-hosted
                // server, may never be saved where the person can find it.
                FormField(label: "Username", text: $username, error: errors.username,
                          contentType: isCreate ? .none : .username)
                FormField(label: "Password", text: $password, secure: true, error: errors.password,
                          contentType: isCreate ? .newSecret : .password)
                if isCreate {
                    FormField(label: "Confirm password", text: $confirm, secure: true, error: errors.confirm,
                              contentType: .newSecret)
                }
                advanced
                if let general = errors.general {
                    Label(general, systemImage: "exclamationmark.triangle.fill")
                        .font(.callout)
                        .foregroundStyle(theme.danger)
                }
                Button(action: submit) {
                    HStack(spacing: 8) {
                        if busy { ProgressView().controlSize(.small).tint(theme.onAccent) }
                        Text(isCreate ? "Create account" : "Sign in")
                    }
                }
                .buttonStyle(AccentButtonStyle())
                .disabled(busy)
                .keyboardShortcut(.defaultAction)
                if !isCreate {
                    Label("One account, one device: signing in here signs this account out on any other device, and that device deletes its keys.",
                          systemImage: "iphone.and.arrow.forward")
                        .font(.footnote)
                        .foregroundStyle(theme.textMuted)
                }
                Button(isCreate ? "Already have an account? Sign in" : "New here? Create an account") {
                    errors = FieldErrors()
                    app.phase = .auth(isCreate ? .signIn : .create)
                }
                .buttonStyle(.plain)
                .font(.callout.weight(.medium))
                .foregroundStyle(theme.accentText)
                .frame(maxWidth: .infinity)
            }
            .padding(28)
            .frame(maxWidth: 420)
            .frame(maxWidth: .infinity)
        }
        .scrollDismissesKeyboardIfAvailable()
        .onSubmit(submit) // Return in any field
        .onAppear {
            if server.isEmpty { server = app.server }
            if username.isEmpty, !isCreate { username = app.suggestedUsername }
        }
        .confirmationDialog("Forget the certificate for \(Engine.normalize(server))?",
                            isPresented: $confirmForget, titleVisibility: .visible) {
            Button("Forget and check again", role: .destructive) { Task { await forgetAndRetry() } }
        } message: {
            Text("Only if the server's operator told you its certificate changed. A certificate you didn't expect can mean someone is in the middle. You'll be shown the new fingerprint to compare before anything is sent.")
        }
        .sheet(item: $pendingTrust) { check in
            TrustSheet(check: check) { trusted in
                pendingTrust = nil
                if trusted { Task { await trustAndContinue(check) } } else { busy = false }
            }
            .themedSheet()
        }
        // An error goes once its field is edited.
        .onChange(of: username) { errors.username = nil; errors.general = nil }
        .onChange(of: password) { errors.password = nil; errors.general = nil }
        .onChange(of: confirm) { errors.confirm = nil }
        .onChange(of: server) { errors.server = nil; certificateChanged = false }
    }

    private var header: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack {
                Button {
                    app.authNotice = nil
                    app.phase = .welcome
                } label: {
                    Image(systemName: "chevron.left")
                        .font(.title3.weight(.semibold))
                        .foregroundStyle(theme.textMuted)
                        .frame(width: 32, height: 32)
                }
                .buttonStyle(.plain)
                .accessibilityLabel("Back")
                Spacer()
                MeshMark(size: 36)
            }
            Text(isCreate ? "Create your account" : "Welcome back")
                .font(.system(.largeTitle, design: .rounded).weight(.bold))
                .foregroundStyle(theme.text)
        }
    }

    private var advanced: some View {
        DisclosureGroup(isExpanded: $showAdvanced) {
            VStack(alignment: .leading, spacing: 8) {
                FormField(label: "Server", text: $server, error: errors.server, contentType: .url)
                Text("host:port. The first time, you'll be shown the server's certificate fingerprint to compare.")
                    .font(.footnote)
                    .foregroundStyle(theme.textMuted)
                if certificateChanged {
                    Button("Forget this server's certificate…", role: .destructive) { confirmForget = true }
                        .buttonStyle(.plain)
                        .font(.callout.weight(.medium))
                        .foregroundStyle(theme.danger)
                        .padding(.top, 4)
                }
            }
            .padding(.top, 8)
        } label: {
            Text("Advanced")
                .font(.callout.weight(.medium))
                .foregroundStyle(theme.textMuted)
        }
        .tint(theme.textMuted)
    }

    // MARK: flow

    private func validate() -> Bool {
        var e = FieldErrors()
        let name = username.trimmingCharacters(in: .whitespaces)
        if name.count < 3 || name.count > 32 {
            e.username = "Usernames are 3 to 32 characters."
        }
        // While GoMesh is being tested, any password goes but an empty one.
        if password.isEmpty {
            e.password = "Enter a password."
        } else if password.utf8.count > 512 {
            e.password = "That password is too long."
        }
        if isCreate, e.password == nil, confirm != password {
            e.confirm = "The passwords don't match."
        }
        if server.trimmingCharacters(in: .whitespaces).isEmpty {
            e.server = "Enter the server's address."
            showAdvanced = true
        }
        errors = e
        return e == FieldErrors()
    }

    private func submit() {
        guard !busy, validate() else { return }
        busy = true
        Task {
            do {
                let check = try await app.checkServer(server)
                if check.pinned {
                    await send()
                } else {
                    pendingTrust = check
                }
            } catch let e as EngineError {
                show(e)
                busy = false
            } catch {
                busy = false
            }
        }
    }

    private func trustAndContinue(_ check: ServerCheck) async {
        do {
            try await app.trust(check)
            await send()
        } catch let e as EngineError {
            show(e)
            busy = false
        } catch {
            busy = false
        }
    }

    private func send() async {
        do {
            try await app.submit(mode, server: server, username: username.trimmingCharacters(in: .whitespaces),
                                 password: password)
            password = ""
            confirm = ""
        } catch let e as EngineError {
            show(e)
        } catch {
            errors.general = "\(error)"
        }
        busy = false
    }

    private func forgetAndRetry() async {
        do {
            try await app.forgetServer(server)
        } catch let e as EngineError {
            show(e)
            return
        } catch {
            return
        }
        certificateChanged = false
        errors = FieldErrors()
        submit() // checks the server again, and shows its new fingerprint
    }

    /// Puts an engine error under the field it is about.
    private func show(_ e: EngineError) {
        var f = FieldErrors()
        certificateChanged = e.code == "pin_mismatch"
        switch e.code {
        case "username_taken", "invalid_username":
            f.username = e.message
        case "weak_password":
            f.password = e.message
        case "bad_credentials":
            f.password = e.message
        case "unreachable", "untrusted_server", "pin_mismatch":
            f.server = e.message
            showAdvanced = true
        default:
            f.general = e.message
        }
        errors = f
    }
}

extension View {
    @ViewBuilder func scrollDismissesKeyboardIfAvailable() -> some View {
        #if os(iOS)
        self.scrollDismissesKeyboard(.interactively)
        #else
        self
        #endif
    }
}

extension ServerCheck: Identifiable {
    var id: String { address + fingerprint }
}

/// Shows a server's certificate fingerprint the first time, for the person
/// to compare with the one its operator published.
struct TrustSheet: View {
    @Environment(\.theme) private var theme
    let check: ServerCheck
    let done: (Bool) -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            Label("New server", systemImage: "lock.shield.fill")
                .font(.title2.weight(.bold))
                .foregroundStyle(theme.text)
            Text("This device hasn't connected to **\(check.address)** before. Compare its certificate fingerprint with the one the server's operator gave you. Trust it only if they match.")
                .foregroundStyle(theme.text)
                .fixedSize(horizontal: false, vertical: true)
            // All of it, always: a fingerprint cut short cannot be compared.
            Text(check.fingerprintGroups)
                .font(.system(.callout, design: .monospaced))
                .foregroundStyle(theme.text)
                .lineLimit(nil)
                .fixedSize(horizontal: false, vertical: true)
                .textSelection(.enabled)
                .padding(14)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(theme.surfaceRaised, in: RoundedRectangle(cornerRadius: 10))
                .accessibilityLabel("Fingerprint \(check.fingerprintGroups)")
            Text("Once trusted, GoMesh refuses any other certificate from this address.")
                .font(.footnote)
                .foregroundStyle(theme.textMuted)
            HStack(spacing: 12) {
                Button("Cancel") { done(false) }
                    .buttonStyle(QuietButtonStyle())
                    .keyboardShortcut(.cancelAction)
                Button("Trust") { done(true) }
                    .buttonStyle(AccentButtonStyle())
            }
        }
        .padding(28)
        .frame(minWidth: 320, idealWidth: 460)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top)
        .presentationBackground(theme.bg)
        .presentationDetents([.large])
        .interactiveDismissDisabled()
    }
}
