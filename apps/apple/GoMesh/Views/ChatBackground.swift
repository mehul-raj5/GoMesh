import SwiftUI

/// The chat's background: the theme's `chatBg` with a lattice of faint dots in
/// `chatPattern`. Decorative, so it carries no text and no contrast rule; the
/// dots stay small and sparse so bubbles read over them.
struct ChatBackground: View {
    @Environment(\.theme) private var theme

    var body: some View {
        Canvas { ctx, size in
            let step: CGFloat = 28
            let r: CGFloat = 1.5
            var dots = Path()
            var row = 0
            var y: CGFloat = step / 2
            while y < size.height + step {
                var x: CGFloat = row.isMultiple(of: 2) ? step / 2 : step
                while x < size.width + step {
                    dots.addEllipse(in: CGRect(x: x - r, y: y - r, width: 2 * r, height: 2 * r))
                    x += step
                }
                y += step / 2
                row += 1
            }
            ctx.fill(dots, with: .color(theme.chatPattern))
        }
        .background(theme.chatBg)
        .ignoresSafeArea()
        .accessibilityHidden(true)
    }
}
