// Draws the GoMesh app icon: the mark from the welcome screen (three linked
// dots) on the GoMesh Dark background. Writes the iOS icon (one 1024 px square;
// iOS rounds the corners itself) and the macOS sizes (a rounded square on a
// transparent canvas, as macOS icons carry their own shape) into an asset
// catalog's AppIcon set, with its Contents.json.
//
//   swift design/gen_icon.swift apps/apple/GoMesh/Assets.xcassets/AppIcon.appiconset

import CoreGraphics
import Foundation
import ImageIO
import UniformTypeIdentifiers

func rgb(_ hex: String, _ alpha: CGFloat = 1) -> CGColor {
    let v = UInt32(hex.dropFirst(), radix: 16)!
    return CGColor(srgbRed: CGFloat((v >> 16) & 0xff) / 255, green: CGFloat((v >> 8) & 0xff) / 255,
                   blue: CGFloat(v & 0xff) / 255, alpha: alpha)
}

// GoMesh Dark, from design/themes.json.
let top = rgb("#1e2230"), bottom = rgb("#0e1016")
let line = rgb("#9ca3b8", 0.55)
let dots = [rgb("#8b80ff"), rgb("#0bd8b6"), rgb("#f986c9")] // accent, teal, pink

/// Draws the icon's square face into rect: the background and the mark.
func drawFace(_ ctx: CGContext, in rect: CGRect) {
    let space = CGColorSpace(name: CGColorSpace.sRGB)!
    let gradient = CGGradient(colorsSpace: space, colors: [top, bottom] as CFArray, locations: [0, 1])!
    // Core Graphics puts y = 0 at the bottom, so the light colour starts at maxY.
    ctx.drawLinearGradient(gradient, start: CGPoint(x: rect.midX, y: rect.maxY),
                           end: CGPoint(x: rect.midX, y: rect.minY), options: [])

    // The mark, as MeshMark draws it, filling 72% of the face.
    let s = rect.width * 0.72
    let origin = CGPoint(x: rect.midX - s / 2, y: rect.midY - s / 2 - rect.width * 0.02)
    func pt(_ x: CGFloat, _ y: CGFloat) -> CGPoint { CGPoint(x: origin.x + s * x, y: origin.y + s * (1 - y)) }
    let pts = [pt(0.5, 0.2), pt(0.18, 0.75), pt(0.82, 0.75)]
    ctx.setStrokeColor(line)
    ctx.setLineWidth(s * 0.045)
    ctx.setLineJoin(.round)
    ctx.addLines(between: pts)
    ctx.closePath()
    ctx.strokePath()
    let r = s * 0.13
    for (p, c) in zip(pts, dots) {
        ctx.setFillColor(c)
        ctx.fillEllipse(in: CGRect(x: p.x - r, y: p.y - r, width: 2 * r, height: 2 * r))
    }
}

func image(size: Int, mac: Bool) -> CGImage {
    let ctx = CGContext(data: nil, width: size, height: size, bitsPerComponent: 8, bytesPerRow: 0,
                        space: CGColorSpace(name: CGColorSpace.sRGB)!,
                        bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue)!
    ctx.interpolationQuality = .high
    let full = CGRect(x: 0, y: 0, width: size, height: size)
    if mac {
        // The macOS grid: an 824/1024 rounded square, centred, with a soft shadow.
        let k = CGFloat(size) / 1024
        let face = full.insetBy(dx: 100 * k, dy: 100 * k)
        let shape = CGPath(roundedRect: face, cornerWidth: 185 * k, cornerHeight: 185 * k, transform: nil)
        ctx.saveGState()
        ctx.setShadow(offset: CGSize(width: 0, height: -10 * k), blur: 28 * k, color: CGColor(gray: 0, alpha: 0.35))
        ctx.addPath(shape)
        ctx.setFillColor(bottom)
        ctx.fillPath()
        ctx.restoreGState()
        ctx.addPath(shape)
        ctx.clip()
        drawFace(ctx, in: face)
    } else {
        drawFace(ctx, in: full)
    }
    return ctx.makeImage()!
}

func writePNG(_ img: CGImage, to url: URL) {
    let dest = CGImageDestinationCreateWithURL(url as CFURL, UTType.png.identifier as CFString, 1, nil)!
    CGImageDestinationAddImage(dest, img, nil)
    precondition(CGImageDestinationFinalize(dest), "could not write \(url.path)")
}

guard CommandLine.arguments.count == 2 else {
    print("usage: swift gen_icon.swift <AppIcon.appiconset>")
    exit(2)
}
let dir = URL(fileURLWithPath: CommandLine.arguments[1], isDirectory: true)
try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)

var entries: [[String: String]] = []
writePNG(image(size: 1024, mac: false), to: dir.appendingPathComponent("ios-1024.png"))
entries.append(["filename": "ios-1024.png", "idiom": "universal", "platform": "ios", "size": "1024x1024"])
for points in [16, 32, 128, 256, 512] {
    for scale in [1, 2] {
        let name = "mac-\(points)@\(scale)x.png"
        writePNG(image(size: points * scale, mac: true), to: dir.appendingPathComponent(name))
        entries.append(["filename": name, "idiom": "mac", "scale": "\(scale)x", "size": "\(points)x\(points)"])
    }
}
let contents: [String: Any] = ["images": entries, "info": ["author": "xcode", "version": 1]]
let json = try JSONSerialization.data(withJSONObject: contents, options: [.prettyPrinted, .sortedKeys])
try json.write(to: dir.appendingPathComponent("Contents.json"))
print("wrote \(entries.count) icons to \(dir.path)")
