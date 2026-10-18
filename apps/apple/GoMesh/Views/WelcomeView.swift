import SwiftUI

struct WelcomeView: View {
    @Environment(AppState.self) private var app
    @Environment(\.theme) private var theme

    var body: some View {
        VStack(spacing: 28) {
            Spacer()
            MeshMark(size: 96)
            VStack(spacing: 10) {
                Text("GoMesh")
                    .font(.system(.largeTitle, design: .rounded, weight: .bold))
                    .foregroundStyle(theme.text)
                Text("Private messages, end to end.\nYour keys never leave this device.")
                    .multilineTextAlignment(.center)
                    .font(.body)
                    .foregroundStyle(theme.textMuted)
            }
            HStack(spacing: 8) {
                ForEach(0..<8, id: \.self) { i in
                    Circle().fill(theme.palette[i]).frame(width: 8, height: 8)
                }
            }
            .accessibilityHidden(true)
            Spacer()
            VStack(spacing: 12) {
                Button("Create account") { app.phase = .auth(.create) }
                    .buttonStyle(AccentButtonStyle())
                Button("Sign in") { app.phase = .auth(.signIn) }
                    .buttonStyle(QuietButtonStyle())
            }
            .frame(maxWidth: 360)
        }
        .padding(32)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}
