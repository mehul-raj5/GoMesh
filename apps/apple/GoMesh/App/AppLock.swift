import Foundation
import LocalAuthentication
import Observation
import SwiftUI

/// App Lock: with it on, GoMesh asks for Face ID, Touch ID or the device's
/// passcode (or the Mac's password) when it opens, and again once it has been
/// away for the chosen time. While the app is not in front its windows are
/// covered, so the app switcher's snapshot shows no chats.
///
/// "Away" starts when the app goes to the background on iOS, not when it turns
/// inactive: Control Center, the app switcher and the Face ID prompt itself all
/// make it inactive. On the Mac, where there is no background, it starts when
/// the app stops being the active one, except while it is asking to unlock.
@MainActor @Observable
final class AppLock {
    enum Delay: Int, CaseIterable, Identifiable {
        case immediately = 0, oneMinute = 60, fifteenMinutes = 900
        var id: Int { rawValue }
        var label: String {
            switch self {
            case .immediately: "Immediately"
            case .oneMinute: "After 1 minute"
            case .fifteenMinutes: "After 15 minutes"
            }
        }
    }

    static let enabledKey = "appLock.enabled"
    static let delayKey = "appLock.delay"

    private(set) var enabled: Bool
    var delay: Delay { didSet { defaults.set(delay.rawValue, forKey: Self.delayKey) } }
    /// Locked: the lock screen is up, and only unlocking takes it down.
    private(set) var isLocked: Bool
    /// Covered: the app is not in front, and App Lock hides what it shows.
    private(set) var isCovered = false
    /// What went wrong with the last attempt to unlock, for the lock screen.
    private(set) var problem: String?
    /// Counts unlocks, for haptic feedback.
    private(set) var unlocks = 0

    /// Asks the person to prove it is them. Replaceable, for the self-test.
    var authenticate: (_ reason: String) async -> AuthResult = AppLock.deviceOwner

    enum AuthResult: Equatable { case success, cancelled, failed(String) }

    private let defaults: UserDefaults
    private var awaySince: Date?
    private var asking = false
    /// Whether this lock has asked by itself yet. It asks once; after a cancel,
    /// the button asks again.
    private var autoAsked = false

    init(defaults: UserDefaults = .standard) {
        self.defaults = defaults
        let on = defaults.bool(forKey: Self.enabledKey)
        enabled = on
        delay = Delay(rawValue: defaults.integer(forKey: Self.delayKey)) ?? .immediately
        isLocked = on
    }

    /// Follows the scene, locking once the app has been away long enough.
    func sceneChanged(_ phase: ScenePhase, now: Date = .now) {
        guard enabled else {
            isCovered = false
            return
        }
        switch phase {
        case .active:
            isCovered = false
            if let since = awaySince, now.timeIntervalSince(since) >= TimeInterval(delay.rawValue) {
                isLocked = true
                autoAsked = false
            }
            awaySince = nil
        case .background:
            isCovered = true
            markAway(now)
        default:
            isCovered = true
            #if os(macOS)
            markAway(now)
            #endif
        }
    }

    private func markAway(_ now: Date) {
        if !asking, !isLocked, awaySince == nil { awaySince = now }
    }

    /// Asks to unlock when the lock screen first shows. Cancelling the prompt
    /// makes the app inactive and active again, which must not ask again.
    func unlockOnAppear() async {
        guard !autoAsked else { return }
        autoAsked = true
        await unlock()
    }

    /// Asks to unlock, once at a time.
    func unlock() async {
        guard isLocked, !asking else { return }
        asking = true
        defer { asking = false }
        switch await authenticate("Unlock GoMesh") {
        case .success:
            isLocked = false
            problem = nil
            awaySince = nil
            unlocks += 1
        case .cancelled:
            problem = nil
        case let .failed(message):
            problem = message
        }
    }

    /// Turns App Lock on, once the person has shown they can unlock, or off.
    /// Returns why it could not be turned on.
    func setEnabled(_ on: Bool) async -> String? {
        guard on != enabled else { return nil }
        if on {
            if let why = Self.unavailableReason() { return why }
            asking = true
            let result = await authenticate("Turn on App Lock")
            asking = false
            switch result {
            case .success: break
            case .cancelled: return ""
            case let .failed(message): return message
            }
        }
        enabled = on
        defaults.set(on, forKey: Self.enabledKey)
        if !on {
            isLocked = false
            isCovered = false
            awaySince = nil
        }
        return nil
    }

    /// What unlocking uses on this device, for the settings and the lock screen.
    static var methodName: String {
        let context = LAContext()
        _ = context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil)
        switch context.biometryType {
        case .faceID: return "Face ID"
        case .touchID: return "Touch ID"
        case .opticID: return "Optic ID"
        default:
            #if os(macOS)
            return "your password"
            #else
            return "your passcode"
            #endif
        }
    }

    /// Why App Lock cannot be used here, or nil if it can.
    static func unavailableReason() -> String? {
        var error: NSError?
        if LAContext().canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) { return nil }
        #if os(macOS)
        return "Set a password for this Mac's user to use App Lock."
        #else
        return "Set a passcode for this device to use App Lock."
        #endif
    }

    /// The real check: biometrics, falling back to the device's passcode or the
    /// Mac's password.
    nonisolated static func deviceOwner(_ reason: String) async -> AuthResult {
        let context = LAContext()
        do {
            return try await context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason)
                ? .success : .failed("That didn't work. Try again.")
        } catch let error as LAError {
            switch error.code {
            case .userCancel, .systemCancel, .appCancel: return .cancelled
            case .passcodeNotSet: return .failed("Set a passcode for this device to use App Lock.")
            case .biometryLockout: return .failed("Too many attempts. Use your passcode.")
            default: return .failed(error.localizedDescription)
            }
        } catch {
            return .failed(error.localizedDescription)
        }
    }
}

/// The lock screen over the main window.
struct LockScreen: View {
    @Environment(AppLock.self) private var lock
    @Environment(\.theme) private var theme
    @Environment(\.scenePhase) private var scenePhase

    var body: some View {
        VStack(spacing: 18) {
            Spacer()
            MeshMark(size: 72)
            Text("GoMesh is locked")
                .font(.title2.weight(.bold))
                .foregroundStyle(theme.text)
            if let problem = lock.problem {
                Text(problem)
                    .font(.callout)
                    .foregroundStyle(theme.danger)
                    .multilineTextAlignment(.center)
            }
            Button {
                Task { await lock.unlock() }
            } label: {
                Label("Unlock with \(AppLock.methodName)", systemImage: "lock.open.fill")
                    .font(.headline)
                    .padding(.horizontal, 22)
                    .padding(.vertical, 12)
                    .foregroundStyle(theme.onAccent)
                    .background(theme.accent, in: Capsule())
            }
            .buttonStyle(.plain)
            Spacer()
        }
        .padding(32)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(theme.bg.ignoresSafeArea())
        .accessibilityElement(children: .contain)
        .accessibilityAddTraits(.isModal)
        // Ask straight away when the app comes to the front locked.
        .task(id: scenePhase) {
            if scenePhase == .active { await lock.unlockOnAppear() }
        }
    }
}

/// What covers a window while the app is not in front, or a sheet while the
/// app is locked.
struct LockCover: View {
    @Environment(\.theme) private var theme

    var body: some View {
        ZStack {
            theme.bg.ignoresSafeArea()
            MeshMark(size: 64)
        }
        .accessibilityLabel("GoMesh is locked")
    }
}
