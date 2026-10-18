import Foundation

/// Times and dates as chat screens show them.
enum ChatFormat {
    /// The chat list: a time today, a weekday this week, a date before that.
    static func listTime(_ date: Date, now: Date = .now) -> String {
        let cal = Calendar.current
        if cal.isDate(date, inSameDayAs: now) {
            return date.formatted(date: .omitted, time: .shortened)
        }
        if let days = cal.dateComponents([.day], from: cal.startOfDay(for: date), to: cal.startOfDay(for: now)).day {
            if days == 1 { return String(localized: "Yesterday") }
            if days < 7 { return date.formatted(.dateTime.weekday(.wide)) }
        }
        return date.formatted(date: .numeric, time: .omitted)
    }

    /// A day separator in a chat.
    static func day(_ date: Date, now: Date = .now) -> String {
        let cal = Calendar.current
        if cal.isDate(date, inSameDayAs: now) { return String(localized: "Today") }
        if let y = cal.date(byAdding: .day, value: -1, to: now), cal.isDate(date, inSameDayAs: y) {
            return String(localized: "Yesterday")
        }
        return date.formatted(.dateTime.weekday(.wide).day().month(.wide).year())
    }

    static func time(_ date: Date) -> String { date.formatted(date: .omitted, time: .shortened) }

    static func size(_ bytes: Int64) -> String { ByteCountFormatter.string(fromByteCount: bytes, countStyle: .file) }
}

/// What the chat list and the detail pane are showing.
enum ChatSelection: Hashable {
    /// A chat of the signed-in account.
    case live(String)
    /// A chat kept on this device for another account: read-only.
    case kept(account: String, chat: String)

    var chatID: String {
        switch self {
        case let .live(id): id
        case let .kept(_, chat): chat
        }
    }
}
