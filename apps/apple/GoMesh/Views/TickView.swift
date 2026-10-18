import SwiftUI

/// What the ticks under one of your messages say.
enum TickState: Equatable {
    /// Not accepted by the server yet.
    case clock
    /// The server has it.
    case sent
    /// On every recipient's device.
    case delivered
    /// Every recipient has read it.
    case read
    case failed

    /// From what the engine reports. `delivery` comes from the receipts and is
    /// absent from an engine without them; then the device's own `status`
    /// ("queued", "sent", "failed") is all there is, and a message that went
    /// shows as sent.
    init(status: String, delivery: String?) {
        if status == "failed" { self = .failed; return }
        switch delivery {
        case "read": self = .read
        case "delivered": self = .delivered
        case "accepted": self = .sent
        case "pending": self = .clock
        default: self = status == "queued" ? .clock : .sent
        }
    }

    init(_ m: ChatMessage) { self.init(status: m.status, delivery: m.delivery) }

    /// How VoiceOver reads it, with who of how many for a group.
    func spoken(delivered: Int? = nil, read: Int? = nil, total: Int? = nil) -> String {
        let group = (total ?? 0) > 1 ? total : nil
        switch self {
        case .clock: return String(localized: "Waiting to send")
        case .sent: return String(localized: "Sent")
        case .failed: return String(localized: "Not sent")
        case .delivered:
            if let group, let delivered { return String(localized: "Delivered to \(delivered) of \(group)") }
            return String(localized: "Delivered")
        case .read:
            if let group, let read { return String(localized: "Read by \(read) of \(group)") }
            return String(localized: "Read")
        }
    }
}

/// The ticks under an outgoing message: a clock, one tick, two ticks, or two
/// ticks in the theme's `tickRead` colour. Drawn as shapes, so they scale with
/// Dynamic Type and take their colour from the ground they sit on.
struct TickView: View {
    @Environment(\.theme) private var theme
    let state: TickState
    /// The colour of the clock and of plain ticks; the theme's `metaOut`, for
    /// the outgoing bubble.
    var plain: Color?
    /// The colour of read ticks; the theme's `tickRead`.
    var read: Color?
    var delivered: Int?
    var readBy: Int?
    var total: Int?
    @ScaledMetric(relativeTo: .caption2) private var unit: CGFloat = 1

    var body: some View {
        let plain = plain ?? theme.metaOut
        Group {
            switch state {
            case .clock:
                Image(systemName: "clock")
                    .font(.system(size: 10 * unit, weight: .semibold))
                    .foregroundStyle(plain)
                    .frame(width: 17 * unit, height: 10 * unit, alignment: .trailing)
            case .failed:
                Image(systemName: "exclamationmark.circle.fill")
                    .font(.system(size: 11 * unit))
                    .foregroundStyle(theme.danger)
                    .frame(width: 17 * unit, height: 10 * unit, alignment: .trailing)
            case .sent:
                ticks(count: 1, color: plain)
            case .delivered:
                ticks(count: 2, color: plain)
            case .read:
                ticks(count: 2, color: read ?? theme.tickRead)
            }
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(state.spoken(delivered: delivered, read: readBy, total: total))
    }

    private func ticks(count: Int, color: Color) -> some View {
        ZStack(alignment: .leading) {
            if count == 2 { Tick().stroke(color, style: stroke).frame(width: 11 * unit, height: 9 * unit).offset(x: 5 * unit) }
            Tick().stroke(color, style: stroke).frame(width: 11 * unit, height: 9 * unit)
        }
        .frame(width: 17 * unit, height: 10 * unit, alignment: .leading)
    }

    private var stroke: StrokeStyle { StrokeStyle(lineWidth: 1.5 * unit, lineCap: .round, lineJoin: .round) }
}

/// One tick mark, inset so its round caps stay inside the frame.
private struct Tick: Shape {
    func path(in r: CGRect) -> Path {
        var p = Path()
        p.move(to: CGPoint(x: r.minX + 0.75, y: r.minY + r.height * 0.55))
        p.addLine(to: CGPoint(x: r.minX + r.width * 0.36, y: r.maxY - 0.75))
        p.addLine(to: CGPoint(x: r.maxX - 0.75, y: r.minY + 0.75))
        return p
    }
}
