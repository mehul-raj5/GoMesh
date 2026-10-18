import PhotosUI
import QuickLook
import SwiftUI
import UniformTypeIdentifiers

extension Image {
    /// An image from encoded data, such as a thumbnail.
    init?(encoded data: Data) {
        #if os(macOS)
        guard let img = NSImage(data: data) else { return nil }
        self.init(nsImage: img)
        #else
        guard let img = UIImage(data: data) else { return nil }
        self.init(uiImage: img)
        #endif
    }
}

/// A file in a message: its thumbnail for an image, or its name and size.
struct MediaBubbleContent: View {
    @Environment(\.theme) private var theme
    let media: MediaInfo
    let outgoing: Bool
    let open: () -> Void

    var body: some View {
        Button(action: open) {
            if let data = media.thumbnail, let image = Image(encoded: data) {
                image
                    .resizable()
                    .scaledToFill()
                    .frame(maxWidth: 240, maxHeight: 240)
                    .clipShape(RoundedRectangle(cornerRadius: 12, style: .continuous))
                    .accessibilityLabel("Photo \(media.fileName)")
            } else {
                HStack(spacing: 10) {
                    Image(systemName: "doc.fill")
                        .font(.title2)
                    VStack(alignment: .leading, spacing: 2) {
                        Text(media.fileName).font(.body.weight(.medium)).lineLimit(2)
                        Text(ChatFormat.size(media.size)).font(.caption)
                    }
                }
                .foregroundStyle(outgoing ? theme.onBubbleOut : theme.onBubbleIn)
            }
        }
        .buttonStyle(.plain)
        .disabled(media.mediaID == nil)
        .accessibilityHint(media.mediaID == nil ? "Not kept on this device" : "Opens the file")
    }
}

/// A file on its way, with its progress, or the news that it did not make it.
struct TransferRow: View {
    @Environment(AppState.self) private var app
    @Environment(\.theme) private var theme
    let transfer: Transfer

    var body: some View {
        HStack {
            if !transfer.incoming { Spacer(minLength: 48) }
            VStack(alignment: .leading, spacing: 6) {
                Label(label, systemImage: transfer.failed ? "exclamationmark.circle.fill"
                                          : (transfer.incoming ? "arrow.down.circle" : "arrow.up.circle"))
                    .font(.callout)
                    .foregroundStyle(transfer.failed ? theme.danger : theme.text)
                if transfer.failed {
                    Button("Dismiss") { app.dismissTransfer(transfer.id) }
                        .font(.caption)
                        .buttonStyle(.plain)
                        .foregroundStyle(theme.accentText)
                } else {
                    ProgressView(value: transfer.progress).tint(theme.accentText).frame(width: 180)
                }
            }
            .padding(10)
            .background(theme.surfaceRaised, in: RoundedRectangle(cornerRadius: 14, style: .continuous))
            if transfer.incoming { Spacer(minLength: 48) }
        }
        .padding(.top, 6)
    }

    private var label: String {
        if transfer.failed {
            return transfer.incoming ? String(localized: "Couldn't receive \(transfer.fileName)")
                                     : String(localized: "Couldn't send \(transfer.fileName)")
        }
        return transfer.incoming ? String(localized: "Receiving \(transfer.fileName)")
                                 : String(localized: "Sending \(transfer.fileName)")
    }
}

/// The attach button: a photo or a file on the iPhone, a file on the Mac.
struct AttachButton: View {
    @Environment(AppState.self) private var app
    @Environment(\.theme) private var theme
    let chatID: String
    @ScaledMetric(relativeTo: .body) private var buttonSize: CGFloat = 38
    @State private var importing = false
    @State private var photo: PhotosPickerItem?
    @State private var choosingPhoto = false
    @State private var error: String?

    var body: some View {
        Menu {
            #if os(iOS)
            Button("Photo", systemImage: "photo") { choosingPhoto = true }
            #endif
            Button("File", systemImage: "doc") { importing = true }
        } label: {
            Image(systemName: "paperclip")
                .font(.body.weight(.semibold))
                .foregroundStyle(theme.textMuted)
                .frame(width: buttonSize, height: buttonSize)
        }
        .menuStyle(.button)
        .buttonStyle(.plain)
        .menuIndicator(.hidden)
        .fixedSize()
        .disabled(app.connection != .online)
        .accessibilityLabel("Attach")
        .fileImporter(isPresented: $importing, allowedContentTypes: [.item]) { result in
            if case let .success(url) = result { send(url) }
        }
        .photosPicker(isPresented: $choosingPhoto, selection: $photo, matching: .images)
        .onChange(of: photo) {
            guard let item = photo else { return }
            photo = nil
            Task {
                do {
                    guard let data = try await item.loadTransferable(type: Data.self) else { return }
                    let ext = item.supportedContentTypes.first?.preferredFilenameExtension ?? "jpg"
                    try await app.sendData(PhotoPrivacy.withoutLocation(data), fileName: "Photo.\(ext)", to: chatID)
                } catch let e as EngineError { app.toast = e.message }
                catch { app.toast = "\(error.localizedDescription)" }
            }
        }
    }

    private func send(_ url: URL) {
        Task {
            do { try await app.sendFile(url, to: chatID) }
            catch let e as EngineError { app.toast = e.message }
            catch { app.toast = error.localizedDescription }
        }
    }
}
