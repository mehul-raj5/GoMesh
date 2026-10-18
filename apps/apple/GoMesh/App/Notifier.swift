import Foundation
import UserNotifications

/// Local notifications for messages that arrive while their chat is not on
/// screen. The system keeps a notification's text in its own database, outside
/// the app's encryption, so by default it says only "New message"; the sender
/// and the text are an opt-in setting. There are no push notifications: the
/// app hears of a message only while it is running.
@MainActor
final class Notifier: NSObject, UNUserNotificationCenterDelegate {
    static let shared = Notifier()
    static let previewsKey = "notifications.showPreviews"

    weak var app: AppState?
    private var asked = false

    func start(app: AppState) {
        self.app = app
        UNUserNotificationCenter.current().delegate = self
    }

    /// Asks once, after the first sign-in on a device.
    func requestPermission() {
        guard !asked else { return }
        asked = true
        Task {
            _ = try? await UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound, .badge])
        }
    }

    var showPreviews: Bool { UserDefaults.standard.bool(forKey: Self.previewsKey) }

    /// A message arrived in `chatID`. `title` and `body` are shown only if the
    /// person chose previews.
    func messageArrived(chatID: String, title: String, body: String) {
        let content = UNMutableNotificationContent()
        if showPreviews {
            content.title = title
            content.body = body
        } else {
            content.title = "GoMesh"
            content.body = String(localized: "New message")
        }
        content.sound = .default
        // The chat's ID is an opaque hash; it is what lets a tap open the chat.
        content.userInfo = ["chat": chatID]
        content.threadIdentifier = chatID
        let request = UNNotificationRequest(identifier: UUID().uuidString, content: content, trigger: nil)
        UNUserNotificationCenter.current().add(request)
    }

    func setBadge(_ count: Int) {
        UNUserNotificationCenter.current().setBadgeCount(count)
    }

    /// Removes everything shown, and the badge: on sign-out.
    func clearAll() {
        UNUserNotificationCenter.current().removeAllDeliveredNotifications()
        UNUserNotificationCenter.current().removeAllPendingNotificationRequests()
        setBadge(0)
    }

    /// Clears what was shown for a chat once it is read.
    func clear(chatID: String) {
        let center = UNUserNotificationCenter.current()
        center.getDeliveredNotifications { delivered in
            let ids = delivered.filter { ($0.request.content.userInfo["chat"] as? String) == chatID }.map(\.request.identifier)
            center.removeDeliveredNotifications(withIdentifiers: ids)
        }
    }

    nonisolated func userNotificationCenter(_ center: UNUserNotificationCenter, willPresent notification: UNNotification)
        async -> UNNotificationPresentationOptions {
        [.banner, .sound, .list]
    }

    nonisolated func userNotificationCenter(_ center: UNUserNotificationCenter, didReceive response: UNNotificationResponse) async {
        let chat = response.notification.request.content.userInfo["chat"] as? String
        await MainActor.run {
            if let chat { Notifier.shared.app?.requestedChat = chat }
        }
    }
}
