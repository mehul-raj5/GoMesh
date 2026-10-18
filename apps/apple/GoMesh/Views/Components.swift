import SwiftUI

/// A filled button in the theme's accent.
struct AccentButtonStyle: ButtonStyle {
    @Environment(\.theme) private var theme
    @Environment(\.isEnabled) private var isEnabled

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.body.weight(.semibold))
            .foregroundStyle(theme.onAccent)
            .frame(maxWidth: .infinity, minHeight: 44)
            .background(theme.accent.opacity(isEnabled ? (configuration.isPressed ? 0.8 : 1) : 0.45),
                        in: RoundedRectangle(cornerRadius: 12, style: .continuous))
            .contentShape(Rectangle())
    }
}

/// A quiet button: the accent as text on a raised surface.
struct QuietButtonStyle: ButtonStyle {
    @Environment(\.theme) private var theme

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.body.weight(.semibold))
            .foregroundStyle(theme.text)
            .frame(maxWidth: .infinity, minHeight: 44)
            .background(theme.surfaceRaised.opacity(configuration.isPressed ? 0.7 : 1),
                        in: RoundedRectangle(cornerRadius: 12, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: 12, style: .continuous).stroke(theme.border))
            .contentShape(Rectangle())
    }
}

/// A labelled text field with room for an error under it.
struct FormField: View {
    @Environment(\.theme) private var theme
    let label: String
    @Binding var text: String
    var secure = false
    var error: String?
    var contentType: ContentKind = .none

    /// `newSecret` is a password being chosen, which must not be offered a
    /// generated one: no content type at all still gets the system's strong
    /// password cover, and `.oneTimeCode` is what stops it.
    enum ContentKind { case none, username, password, newSecret, url }

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(label)
                .font(.footnote.weight(.medium))
                .foregroundStyle(theme.textMuted)
            Group {
                if secure {
                    SecureField("", text: $text)
                } else {
                    TextField("", text: $text)
                }
            }
            .textFieldStyle(.plain)
            .autocorrectionDisabled()
            #if os(iOS)
            .textInputAutocapitalization(.never)
            .textContentType(iosContentType)
            #endif
            .foregroundStyle(theme.text)
            .padding(.horizontal, 12)
            .frame(minHeight: 42)
            .background(theme.surfaceRaised, in: RoundedRectangle(cornerRadius: 10, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: 10, style: .continuous)
                .stroke(error == nil ? theme.border : theme.danger, lineWidth: error == nil ? 1 : 1.5))
            .accessibilityLabel(label)
            if let error {
                Label(error, systemImage: "exclamationmark.circle.fill")
                    .font(.footnote)
                    .foregroundStyle(theme.danger)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    #if os(iOS)
    private var iosContentType: UITextContentType? {
        switch contentType {
        case .none: nil
        case .username: .username
        case .password: .password
        case .newSecret: .oneTimeCode
        case .url: .URL
        }
    }
    #endif
}

/// A round avatar: the first letter on a color of the theme's palette.
struct Avatar: View {
    @Environment(\.theme) private var theme
    let name: String
    var isGroup = false
    var size: CGFloat = 40
    /// On the chat list's selected row: the theme's `onSelectedRow` stands in
    /// for the palette, which would not read on it.
    var onSelectedRow = false

    var body: some View {
        let wash = onSelectedRow ? theme.onSelectedRow : theme.color(for: name)
        let ink = onSelectedRow ? theme.onSelectedRow : theme.nameColor(for: name)
        ZStack {
            Circle().fill(wash.opacity(0.22))
            if isGroup {
                Image(systemName: "person.2.fill").font(.system(size: size * 0.38)).foregroundStyle(ink)
            } else {
                Text(String(name.prefix(1)).uppercased())
                    .font(.system(size: size * 0.45, weight: .semibold, design: .rounded))
                    .foregroundStyle(ink)
            }
        }
        .frame(width: size, height: size)
        .accessibilityHidden(true)
    }
}

/// The connection, as a small pill.
struct ConnectionPill: View {
    @Environment(\.theme) private var theme
    let connection: AppState.Connection

    var body: some View {
        let (label, color): (String, Color) = switch connection {
        case .online: ("Online", theme.success)
        case .connecting: ("Connecting…", theme.warning)
        case .offline: ("Offline", theme.danger)
        }
        HStack(spacing: 6) {
            Circle().fill(color).frame(width: 8, height: 8)
            Text(label).font(.caption.weight(.medium)).foregroundStyle(theme.textMuted)
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 5)
        .background(theme.surfaceRaised, in: Capsule())
        .accessibilityElement(children: .combine)
    }
}

/// The GoMesh mark: three linked nodes in the theme's colors.
struct MeshMark: View {
    @Environment(\.theme) private var theme
    var size: CGFloat = 72

    var body: some View {
        Canvas { ctx, sz in
            let s = sz.width
            let pts = [CGPoint(x: s * 0.5, y: s * 0.2), CGPoint(x: s * 0.18, y: s * 0.75), CGPoint(x: s * 0.82, y: s * 0.75)]
            var path = Path()
            path.move(to: pts[0]); path.addLine(to: pts[1]); path.addLine(to: pts[2]); path.closeSubpath()
            ctx.stroke(path, with: .color(theme.textMuted.opacity(0.5)), lineWidth: s * 0.045)
            let colors = [theme.accent, theme.palette[4], theme.palette[7]]
            for (p, c) in zip(pts, colors) {
                let r = s * 0.13
                ctx.fill(Path(ellipseIn: CGRect(x: p.x - r, y: p.y - r, width: 2 * r, height: 2 * r)), with: .color(c))
            }
        }
        .frame(width: size, height: size)
        .accessibilityHidden(true)
    }
}
