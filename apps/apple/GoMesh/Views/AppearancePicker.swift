import SwiftUI

/// Settings → Appearance: Auto, then every light theme, then every dark one,
/// each with a small preview of itself. Choosing one applies it at once.
struct AppearancePicker: View {
    @Environment(ThemeStore.self) private var store
    @Environment(\.theme) private var theme

    var body: some View {
        @Bindable var store = store
        List {
            Section {
                row(selected: store.isAuto, action: { store.selection = ThemeStore.auto }) {
                    AutoSwatch(light: Theme.named(store.autoLight) ?? .fallback,
                               dark: Theme.named(store.autoDark) ?? .fallback)
                } label: {
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Auto").foregroundStyle(theme.text)
                        Text(Self.followsText).font(.caption).foregroundStyle(theme.textMuted)
                    }
                }
                if store.isAuto {
                    Picker("Light mode", selection: $store.autoLight) {
                        ForEach(Theme.light) { Text($0.name).tag($0.id) }
                    }
                    .foregroundStyle(theme.text)
                    Picker("Dark mode", selection: $store.autoDark) {
                        ForEach(Theme.dark) { Text($0.name).tag($0.id) }
                    }
                    .foregroundStyle(theme.text)
                }
            }
            .listRowBackground(theme.surface)

            Section {
                ForEach(Theme.light) { themeRow($0) }
            } header: {
                Text("LIGHT").font(.caption.weight(.semibold)).foregroundStyle(theme.textMuted)
            }
            .listRowBackground(theme.surface)

            Section {
                ForEach(Theme.dark) { themeRow($0) }
            } header: {
                Text("DARK").font(.caption.weight(.semibold)).foregroundStyle(theme.textMuted)
            }
            .listRowBackground(theme.surface)
        }
        .scrollContentBackground(.hidden)
        .background(theme.bg)
        .navigationTitle("Appearance")
        .toolbarBackground(theme.surface, for: .automatic)
        .tint(theme.accentText)
    }

    static var followsText: String {
        #if os(macOS)
        "Follows your Mac"
        #else
        "Follows your iPhone"
        #endif
    }

    private func themeRow(_ t: Theme) -> some View {
        row(selected: !store.isAuto && store.selection == t.id, action: { store.selection = t.id }) {
            ThemeSwatch(theme: t)
        } label: {
            Text(t.name).foregroundStyle(theme.text)
        }
    }

    private func row<S: View, L: View>(selected: Bool, action: @escaping () -> Void,
                                       @ViewBuilder swatch: () -> S, @ViewBuilder label: () -> L) -> some View {
        Button(action: action) {
            HStack(spacing: 14) {
                swatch()
                label()
                Spacer()
                if selected {
                    Image(systemName: "checkmark")
                        .font(.body.weight(.semibold))
                        .foregroundStyle(theme.accentText)
                }
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityAddTraits(selected ? .isSelected : [])
    }
}

/// A theme in miniature: its background, a muted line, an incoming bubble
/// and an outgoing one in its accent.
struct ThemeSwatch: View {
    let theme: Theme
    var width: CGFloat = 46
    var height: CGFloat = 32

    var body: some View {
        ZStack(alignment: .topLeading) {
            theme.bg
            VStack(alignment: .leading, spacing: 3) {
                Capsule().fill(theme.bubbleIn).frame(width: width * 0.5, height: 6)
                HStack {
                    Spacer(minLength: 0)
                    Capsule().fill(theme.bubbleOut).frame(width: width * 0.55, height: 6)
                }
                Capsule().fill(theme.textMuted.opacity(0.6)).frame(width: width * 0.35, height: 3)
            }
            .padding(5)
        }
        .frame(width: width, height: height)
        .clipShape(RoundedRectangle(cornerRadius: 7, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: 7, style: .continuous).stroke(theme.border, lineWidth: 1))
        .accessibilityHidden(true)
    }
}

/// Auto: the light theme and the dark theme, split on the diagonal.
struct AutoSwatch: View {
    let light: Theme
    let dark: Theme

    var body: some View {
        ZStack {
            ThemeSwatch(theme: light)
            ThemeSwatch(theme: dark)
                .mask(Path { p in
                    p.move(to: CGPoint(x: 46, y: 0)); p.addLine(to: CGPoint(x: 46, y: 32)); p.addLine(to: CGPoint(x: 0, y: 32))
                    p.closeSubpath()
                })
        }
        .frame(width: 46, height: 32)
        .accessibilityHidden(true)
    }
}
