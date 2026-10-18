import Foundation
import ImageIO
import UniformTypeIdentifiers

/// Photos from the library carry where they were taken. A photo sent from the
/// picker has that removed first; everything else about it is kept.
enum PhotoPrivacy {
    /// The photo without its location, or the photo as it was if it cannot be
    /// read as an image (a file that is not one is sent unchanged).
    static func withoutLocation(_ data: Data) -> Data {
        guard let source = CGImageSourceCreateWithData(data as CFData, nil),
              let type = CGImageSourceGetType(source),
              CGImageSourceGetCount(source) > 0 else { return data }
        let out = NSMutableData()
        guard let dest = CGImageDestinationCreateWithData(out as CFMutableData, type, 1, nil) else { return data }
        // kCFNull removes a property from what the source carries.
        let strip: [CFString: Any] = [kCGImagePropertyGPSDictionary: kCFNull as Any]
        CGImageDestinationAddImageFromSource(dest, source, 0, strip as CFDictionary)
        guard CGImageDestinationFinalize(dest) else { return data }
        return out as Data
    }

    /// Whether data is an image that says where it was taken.
    static func hasLocation(_ data: Data) -> Bool {
        guard let source = CGImageSourceCreateWithData(data as CFData, nil),
              let props = CGImageSourceCopyPropertiesAtIndex(source, 0, nil) as? [CFString: Any] else { return false }
        return props[kCGImagePropertyGPSDictionary] != nil
    }
}
