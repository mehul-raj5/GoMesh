#if DEBUG
import ImageIO
import SwiftUI
import UniformTypeIdentifiers

/// A Debug-only self-test the Mac build runs when launched with -autotest, so
/// sign-up can be checked from a script: it launches as usual, trusts the
/// server only if its fingerprint is the one given, creates or signs in to an
/// account, renders screens in every theme to PNG files, writes what happened
/// to result.json, and quits. Everything goes to the app's temporary folder.
///
///   GOMESH_AUTOTEST_SERVER  host:port
///   GOMESH_AUTOTEST_FP      the fingerprint to accept, 64 hex characters
///   GOMESH_AUTOTEST_USER    the username; the password is the user's name
///                           repeated to 12 characters, never anything real
///   GOMESH_AUTOTEST_MODE    "create" (default), "signIn" (signing out whoever is
///                           signed in first), "resume", "render", or "chat":
///                           resume, open a chat with GOMESH_AUTOTEST_PEER, send
///                           GOMESH_AUTOTEST_TEXT, and wait for a reply that
///                           contains it. A peer of "#name" is a group by name.
///                           "lock" checks App Lock's timing with a stand-in for
///                           Touch ID, on settings of its own, and renders the
///                           lock screen.
@MainActor
enum AutoTest {
    static var requested: Bool { CommandLine.arguments.contains("-autotest") }

    static func run(app: AppState, themes: ThemeStore) async {
        let env = ProcessInfo.processInfo.environment
        let out = FileManager.default.temporaryDirectory.appendingPathComponent("autotest", isDirectory: true)
        try? FileManager.default.removeItem(at: out)
        try? FileManager.default.createDirectory(at: out, withIntermediateDirectories: true)
        var result: [String: String] = [:]
        func finish() -> Never {
            if let data = try? JSONSerialization.data(withJSONObject: result, options: [.prettyPrinted, .sortedKeys]) {
                try? data.write(to: out.appendingPathComponent("result.json"))
            }
            exit(0)
        }

        await app.launch()
        result["launchPhase"] = "\(app.phase)"
        result["vault"] = app.vaultDescription
        let mode = env["GOMESH_AUTOTEST_MODE"] ?? "create"

        if mode == "render" {
            render(to: out, themes: themes, result: &result)
            finish()
        }
        if mode == "lock" {
            await checkLock(out: out, themes: themes, result: &result)
            finish()
        }
        if mode == "chat" {
            await waitFor { app.connection == .online }
            guard let peer = env["GOMESH_AUTOTEST_PEER"], let text = env["GOMESH_AUTOTEST_TEXT"] else {
                result["error"] = "chat needs GOMESH_AUTOTEST_PEER and GOMESH_AUTOTEST_TEXT"
                finish()
            }
            do {
                // "#name" is a group the account is in, found in its chat list.
                var id: String
                if peer.hasPrefix("#") {
                    app.refreshChats()
                    for _ in 0..<50 where !app.chats.contains(where: { $0.name == String(peer.dropFirst()) }) {
                        try? await Task.sleep(for: .milliseconds(100))
                    }
                    guard let group = app.chats.first(where: { $0.name == String(peer.dropFirst()) }) else {
                        result["error"] = "no group called \(peer.dropFirst())"
                        finish()
                    }
                    id = group.id
                } else {
                    id = try await app.openDirect(peer)
                }
                let model = app.model(for: id)
                await model.loadLatest()
                await model.send(text)
                result["afterSend"] = model.messages.last.map { "\($0.text ?? "") [\($0.status)]" } ?? "nothing kept"
                result["pendingAfterSend"] = "\(model.pending.count)"
                for _ in 0..<100 {
                    await model.loadLatest()
                    if model.messages.contains(where: { !$0.outgoing && ($0.text ?? "").contains(text) }) { break }
                    try? await Task.sleep(for: .milliseconds(100))
                }
                result["messages"] = model.messages.map { m in
                    m.isSystem ? "· \(m.text ?? "")"
                        : "\(m.outgoing ? "me" : (m.senderName ?? "?")): \(m.text ?? m.media.map { "[file \($0.fileName), thumbnail \($0.thumbnail?.count ?? 0) bytes, kept \($0.mediaID != nil)]" } ?? "")"
                }.joined(separator: " | ")
                // With GOMESH_AUTOTEST_EXPORT set, the newest kept file is written
                // out where a script can look at it.
                if env["GOMESH_AUTOTEST_EXPORT"] != nil, let engine = app.engine,
                   let m = model.messages.last(where: { $0.media?.mediaID != nil }), let media = m.media, let mid = media.mediaID {
                    let url = try await engine.exportMedia(account: app.account?.userID ?? "", mediaID: mid,
                                                           fileName: media.fileName, dir: out)
                    result["exported"] = url.path
                }
                app.refreshChats()
                try? await Task.sleep(for: .milliseconds(400))
                result["chats"] = app.chats.map { "\($0.name) unread=\($0.unread) preview=\($0.preview)" }.joined(separator: " | ")
            } catch let e as EngineError {
                result["errorCode"] = e.code
                result["error"] = e.message
            } catch {
                result["error"] = "\(error)"
            }
            finish()
        }
        if mode == "resume" {
            await waitFor { app.connection == .online }
            result["account"] = app.account?.username ?? ""
            result["connection"] = "\(app.connection)"
            finish()
        }

        guard let server = env["GOMESH_AUTOTEST_SERVER"], let user = env["GOMESH_AUTOTEST_USER"],
              let expected = env["GOMESH_AUTOTEST_FP"] else {
            result["error"] = "missing GOMESH_AUTOTEST_* settings"
            finish()
        }
        let password = String(repeating: user, count: 12 / max(user.count, 1) + 1).prefix(12)
        if mode == "signIn", app.phase == .signedIn {
            // One account per device: whoever is signed in here signs out first.
            result["signedOutFirst"] = app.account?.username ?? ""
            await app.signOut(deleteHistory: false)
            await waitFor { app.phase == .welcome }
            result["afterSignOut"] = "\(app.phase)"
        }
        do {
            let check = try await app.checkServer(server)
            result["fingerprint"] = check.fingerprint
            result["pinnedBefore"] = "\(check.pinned)"
            if !check.pinned {
                guard check.fingerprint == expected.lowercased() else {
                    result["error"] = "the server's fingerprint is not the expected one"
                    finish()
                }
                try await app.trust(check)
            }
            try await app.submit(mode == "signIn" ? .signIn : .create, server: server, username: user,
                                 password: String(password))
            await waitFor { app.connection == .online }
            result["phase"] = "\(app.phase)"
            result["account"] = app.account?.username ?? ""
            result["connection"] = "\(app.connection)"
        } catch let e as EngineError {
            result["errorCode"] = e.code
            result["error"] = e.message
        } catch {
            result["error"] = "\(error)"
        }
        render(to: out, themes: themes, result: &result)
        finish()
    }

    /// App Lock with a stand-in authenticator: when it locks, what unlocks it,
    /// and that a prompt making the app inactive does not lock it again.
    private static func checkLock(out: URL, themes: ThemeStore, result: inout [String: String]) async {
        let suite = "gomesh.autotest.lock"
        UserDefaults().removePersistentDomain(forName: suite)
        let lock = AppLock(defaults: UserDefaults(suiteName: suite)!)
        var answer = AppLock.AuthResult.success
        lock.authenticate = { _ in answer }
        var steps: [String] = []
        func note(_ what: String) { steps.append("\(what): locked=\(lock.isLocked) covered=\(lock.isCovered)") }

        note("off")
        answer = .cancelled
        let refused = await lock.setEnabled(true)
        steps.append("enable, cancelled: enabled=\(lock.enabled) why=\(refused ?? "nil")")
        answer = .success
        _ = await lock.setEnabled(true)
        note("enabled")
        lock.delay = .oneMinute
        let t0 = Date()
        lock.sceneChanged(.inactive, now: t0)
        note("inactive")
        lock.sceneChanged(.active, now: t0.addingTimeInterval(30))
        note("back after 30 s")
        lock.sceneChanged(.inactive, now: t0.addingTimeInterval(40))
        lock.sceneChanged(.active, now: t0.addingTimeInterval(101))
        note("back after 61 s")
        answer = .failed("That didn't work. Try again.")
        await lock.unlock()
        note("wrong finger")
        answer = .success
        await lock.unlock()
        note("unlocked")
        _ = await lock.setEnabled(false)
        note("disabled")
        result["lockSteps"] = steps.joined(separator: " | ")

        // The lock screen, in the house themes.
        _ = await lock.setEnabled(true)
        lock.sceneChanged(.inactive, now: t0)
        lock.sceneChanged(.active, now: t0.addingTimeInterval(120))
        var rendered = 0
        for id in ["gomesh-dark", "gomesh-light", "solarized-light"] {
            guard let t = Theme.all.first(where: { $0.id == id }) else { continue }
            let r = ImageRenderer(content: LockScreen().environment(lock).environment(\.theme, t)
                .frame(width: 420, height: 640).background(t.bg))
            r.scale = 1
            if let png = r.pngData() {
                try? png.write(to: out.appendingPathComponent("lock-\(id).png"))
                rendered += 1
            }
        }
        result["lockRendered"] = "\(rendered)"
        UserDefaults().removePersistentDomain(forName: suite)
    }

    private static func waitFor(_ cond: () -> Bool) async {
        for _ in 0..<100 where !cond() {
            try? await Task.sleep(for: .milliseconds(100))
        }
    }

    /// Renders the welcome screen and the theme gallery in every theme.
    private static func render(to out: URL, themes: ThemeStore, result: inout [String: String]) {
        var rendered = 0
        let gallery = ImageRenderer(content: ThemeGallery().frame(width: 900))
        gallery.scale = 2
        if let png = gallery.pngData() {
            try? png.write(to: out.appendingPathComponent("gallery.png"))
            rendered += 1
        }
        for t in Theme.all {
            let view = WelcomeView()
                .environment(AppState())
                .environment(\.theme, t)
                .frame(width: 420, height: 640)
                .background(t.bg)
            let r = ImageRenderer(content: view)
            r.scale = 1
            if let png = r.pngData() {
                try? png.write(to: out.appendingPathComponent("welcome-\(t.id).png"))
                rendered += 1
            }
        }
        result["rendered"] = "\(rendered)"
        result["themes"] = "\(Theme.all.count)"
    }
}

extension ImageRenderer {
    /// The rendering as PNG.
    @MainActor func pngData() -> Data? {
        guard let image = cgImage else { return nil }
        let data = NSMutableData()
        guard let dest = CGImageDestinationCreateWithData(data, UTType.png.identifier as CFString, 1, nil) else { return nil }
        CGImageDestinationAddImage(dest, image, nil)
        return CGImageDestinationFinalize(dest) ? data as Data : nil
    }
}

/// Every theme side by side: its swatch, a pair of bubbles, and its palette.
struct ThemeGallery: View {
    var body: some View {
        let columns = [GridItem(.adaptive(minimum: 200), spacing: 12)]
        LazyVGrid(columns: columns, spacing: 12) {
            ForEach(Theme.all) { t in
                VStack(alignment: .leading, spacing: 8) {
                    HStack {
                        ThemeSwatch(theme: t)
                        Text(t.name).font(.headline).foregroundStyle(t.text)
                    }
                    Text("Hey! Are we still on for tonight?")
                        .font(.callout).foregroundStyle(t.onBubbleIn)
                        .padding(8).background(t.bubbleIn, in: RoundedRectangle(cornerRadius: 12))
                    HStack {
                        Spacer()
                        Text("Yes, see you at 8")
                            .font(.callout).foregroundStyle(t.onBubbleOut)
                            .padding(8).background(t.bubbleOut, in: RoundedRectangle(cornerRadius: 12))
                    }
                    Text("muted text").font(.caption).foregroundStyle(t.textMuted)
                    HStack(spacing: 4) {
                        ForEach(0..<8, id: \.self) { Circle().fill(t.palette[$0]).frame(width: 12, height: 12) }
                    }
                }
                .padding(12)
                .background(t.bg, in: RoundedRectangle(cornerRadius: 14))
                .overlay(RoundedRectangle(cornerRadius: 14).stroke(t.border))
            }
        }
        .padding(16)
        .background(Color.gray.opacity(0.2))
    }
}
#endif
