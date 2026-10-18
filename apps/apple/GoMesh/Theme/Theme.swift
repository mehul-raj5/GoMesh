import SwiftUI

/// One of the app's themes, as design/themes.json defines it.
struct Theme: Identifiable, Sendable, Equatable {
    enum Appearance: String, Decodable, Sendable { case light, dark }

    let id: String
    let name: String
    let appearance: Appearance
    let bg, surface, surfaceRaised, border: Color
    let text, textMuted: Color
    let accent, onAccent: Color
    /// The accent as text and as the tint of buttons and links: contrast-checked
    /// on bg and surface, where the accent itself, kept for fills, may not be.
    let accentText: Color
    let bubbleOut, onBubbleOut, bubbleIn, onBubbleIn: Color
    let danger, warning, success: Color
    /// The chat's background and the dots drawn on it. Optional in themes.json:
    /// the page background, and a faint line of muted text.
    let chatBg, chatPattern: Color
    /// The chat list's selected row and the text on it. Optional: the accent.
    let selectedRow, onSelectedRow: Color
    /// Timestamps inside a bubble, held to 4.5:1 on it. Optional: the bubble's
    /// own text colour.
    let metaOut, metaIn: Color
    /// The "read" ticks on the outgoing bubble, held to 3:1 on it. Optional:
    /// the bubble's text colour, which a double tick still tells from a single.
    let tickRead: Color
    /// Red, orange, yellow, green, teal, blue, purple, pink: avatar washes.
    let palette: [Color]
    /// The palette as text: sender names on the incoming bubble, and an
    /// avatar's letter on its wash. Contrast-checked in every theme.
    let paletteText: [Color]

    var colorScheme: ColorScheme { appearance == .dark ? .dark : .light }

    /// A stable palette slot for a person or a chat.
    static func slot(for key: String) -> Int {
        var h: UInt32 = 2166136261
        for b in key.utf8 { h = (h ^ UInt32(b)) &* 16777619 }
        return Int(h % 8)
    }

    /// A stable colour for a person or a chat, for a wash or a dot.
    func color(for key: String) -> Color { palette[Self.slot(for: key)] }

    /// The same colour, as text that reads on the incoming bubble.
    func nameColor(for key: String) -> Color { paletteText[Self.slot(for: key)] }
}

extension Theme {
    /// Every theme the app ships, in the picker's order.
    static let all: [Theme] = {
        guard let url = Bundle.main.url(forResource: "themes", withExtension: "json"),
              let data = try? Data(contentsOf: url),
              let file = try? JSONDecoder().decode(ThemeFile.self, from: data),
              !file.themes.isEmpty else {
            return [.fallback]
        }
        return file.themes.compactMap(Theme.init(wire:))
    }()

    static var light: [Theme] { all.filter { $0.appearance == .light } }
    static var dark: [Theme] { all.filter { $0.appearance == .dark } }

    static func named(_ id: String) -> Theme? { all.first { $0.id == id } }

    static let defaultLight = "telegram-light"
    static let defaultDark = "telegram-dark"

    /// Only if themes.json is missing from the bundle, which is a build mistake.
    static let fallback = Theme(
        id: "fallback", name: "Fallback", appearance: .light,
        bg: .white, surface: .white, surfaceRaised: Color(white: 0.94), border: Color(white: 0.85),
        text: .black, textMuted: Color(white: 0.35), accent: .blue, onAccent: .white, accentText: .blue,
        bubbleOut: .blue, onBubbleOut: .white, bubbleIn: Color(white: 0.92), onBubbleIn: .black,
        danger: .red, warning: .orange, success: .green,
        chatBg: .white, chatPattern: Color(white: 0.8), selectedRow: .blue, onSelectedRow: .white,
        metaOut: .white, metaIn: .black, tickRead: .white,
        palette: [.red, .orange, .yellow, .green, .teal, .blue, .purple, .pink],
        paletteText: [.red, .orange, .yellow, .green, .teal, .blue, .purple, .pink])
}

private struct ThemeFile: Decodable {
    var version: Int
    var themes: [WireTheme]
}

private struct WireTheme: Decodable {
    var id: String
    var name: String
    var appearance: Theme.Appearance
    var colors: [String: ColorValue]

    enum ColorValue: Decodable {
        case one(String), many([String])
        init(from decoder: Decoder) throws {
            let c = try decoder.singleValueContainer()
            if let s = try? c.decode(String.self) { self = .one(s) } else { self = .many(try c.decode([String].self)) }
        }
    }
}

private extension Theme {
    init?(wire w: WireTheme) {
        func c(_ key: String) -> Color? {
            guard case let .one(hex)? = w.colors[key] else { return nil }
            return Color(hex: hex)
        }
        guard case let .many(hexes)? = w.colors["palette"], hexes.count == 8,
              case let .many(textHexes)? = w.colors["paletteText"], textHexes.count == 8,
              let bg = c("bg"), let surface = c("surface"), let surfaceRaised = c("surfaceRaised"),
              let border = c("border"), let text = c("text"), let textMuted = c("textMuted"),
              let accent = c("accent"), let onAccent = c("onAccent"),
              let bubbleOut = c("bubbleOut"), let onBubbleOut = c("onBubbleOut"),
              let bubbleIn = c("bubbleIn"), let onBubbleIn = c("onBubbleIn"),
              let danger = c("danger"), let warning = c("warning"), let success = c("success") else { return nil }
        let accentText = c("accentText") ?? accent
        // Optional tokens, each falling back as design/gen_themes.py's docstring says and
        // bridge/themes_test.go checks.
        let chatBg = c("chatBg") ?? bg
        let chatPattern = c("chatPattern") ?? textMuted
        let palette = hexes.compactMap(Color.init(hex:))
        let paletteText = textHexes.compactMap(Color.init(hex:))
        guard palette.count == 8, paletteText.count == 8 else { return nil }
        self.init(id: w.id, name: w.name, appearance: w.appearance, bg: bg, surface: surface,
                  surfaceRaised: surfaceRaised, border: border, text: text, textMuted: textMuted,
                  accent: accent, onAccent: onAccent, accentText: accentText,
                  bubbleOut: bubbleOut, onBubbleOut: onBubbleOut,
                  bubbleIn: bubbleIn, onBubbleIn: onBubbleIn, danger: danger, warning: warning,
                  success: success, chatBg: chatBg, chatPattern: chatPattern,
                  selectedRow: c("selectedRow") ?? accent, onSelectedRow: c("onSelectedRow") ?? onAccent,
                  metaOut: c("metaOut") ?? onBubbleOut, metaIn: c("metaIn") ?? onBubbleIn,
                  tickRead: c("tickRead") ?? onBubbleOut, palette: palette, paletteText: paletteText)
    }
}

extension Color {
    /// #rrggbb, in sRGB.
    init?(hex: String) {
        let s = hex.hasPrefix("#") ? hex.dropFirst() : Substring(hex)
        guard s.count == 6, let v = UInt32(s, radix: 16) else { return nil }
        self.init(.sRGB, red: Double((v >> 16) & 0xff) / 255, green: Double((v >> 8) & 0xff) / 255,
                  blue: Double(v & 0xff) / 255, opacity: 1)
    }
}

private struct ThemeKey: EnvironmentKey {
    static let defaultValue: Theme = Theme.named(Theme.defaultLight) ?? .fallback
}

extension EnvironmentValues {
    var theme: Theme {
        get { self[ThemeKey.self] }
        set { self[ThemeKey.self] = newValue }
    }
}
