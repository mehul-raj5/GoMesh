import Observation
import SwiftUI

/// Which theme the person chose: one theme, or Auto, which follows the
/// system's light or dark mode with a theme chosen for each.
@MainActor @Observable
final class ThemeStore {
    static let auto = "auto"

    private let defaults: UserDefaults

    /// "auto" or a theme's ID.
    var selection: String { didSet { defaults.set(selection, forKey: "theme.selection") } }
    var autoLight: String { didSet { defaults.set(autoLight, forKey: "theme.autoLight") } }
    var autoDark: String { didSet { defaults.set(autoDark, forKey: "theme.autoDark") } }

    init(defaults: UserDefaults = .standard) {
        self.defaults = defaults
        selection = defaults.string(forKey: "theme.selection") ?? Self.auto
        autoLight = defaults.string(forKey: "theme.autoLight") ?? Theme.defaultLight
        autoDark = defaults.string(forKey: "theme.autoDark") ?? Theme.defaultDark
    }

    var isAuto: Bool { selection == Self.auto || Theme.named(selection) == nil }

    /// The theme to draw with, given the system's current scheme.
    func resolved(for system: ColorScheme) -> Theme {
        if !isAuto, let t = Theme.named(selection) { return t }
        let id = system == .dark ? autoDark : autoLight
        return Theme.named(id) ?? Theme.named(system == .dark ? Theme.defaultDark : Theme.defaultLight) ?? .fallback
    }

    /// A fixed theme also fixes the system controls' scheme; Auto leaves it
    /// to the system.
    var preferredScheme: ColorScheme? {
        isAuto ? nil : Theme.named(selection)?.colorScheme
    }
}
