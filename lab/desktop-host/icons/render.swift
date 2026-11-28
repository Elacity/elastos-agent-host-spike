// Renders Home's icon (capsules/home/browser/elastos-home-icon.svg) into the PNGs
// make.sh packs for each platform. macOS draws the SVG itself, so no converter is
// needed. Usage: swift render.swift SVG OUT_DIR
import AppKit

let args = CommandLine.arguments
guard args.count == 3 else {
    FileHandle.standardError.write("usage: swift render.swift SVG OUT_DIR\n".data(using: .utf8)!)
    exit(2)
}
let svgURL = URL(fileURLWithPath: args[1])
let out = URL(fileURLWithPath: args[2], isDirectory: true)
let svg = try String(contentsOf: svgURL, encoding: .utf8)

func image(_ text: String) -> NSImage {
    guard let image = NSImage(data: text.data(using: .utf8)!) else {
        FileHandle.standardError.write("macOS could not read the SVG\n".data(using: .utf8)!)
        exit(1)
    }
    return image
}

/// Draws `source` into a `size` square, inset by `inset` of the size on each side.
func render(_ source: NSImage, size: Int, inset: Double, to name: String) throws {
    let rep = NSBitmapImageRep(
        bitmapDataPlanes: nil, pixelsWide: size, pixelsHigh: size, bitsPerSample: 8,
        samplesPerPixel: 4, hasAlpha: true, isPlanar: false, colorSpaceName: .deviceRGB,
        bytesPerRow: 0, bitsPerPixel: 0)!
    rep.size = NSSize(width: size, height: size)
    NSGraphicsContext.saveGraphicsState()
    NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: rep)
    NSGraphicsContext.current?.imageInterpolation = .high
    let margin = Double(size) * inset
    source.draw(
        in: NSRect(x: margin, y: margin, width: Double(size) - 2 * margin, height: Double(size) - 2 * margin),
        from: .zero, operation: .copy, fraction: 1)
    NSGraphicsContext.restoreGraphicsState()
    try rep.representation(using: .png, properties: [:])!.write(to: out.appendingPathComponent(name))
}

let icon = image(svg)

// macOS app icons sit on Apple's grid: an 824-point body on a 1024-point canvas.
let mac = 100.0 / 1024.0
for (points, scale) in [(16, 1), (16, 2), (32, 1), (32, 2), (128, 1), (128, 2), (256, 1), (256, 2), (512, 1), (512, 2)] {
    let suffix = scale == 2 ? "@2x" : ""
    try render(icon, size: points * scale, inset: mac, to: "ElastOS.iconset/icon_\(points)x\(points)\(suffix).png")
}
for size in [16, 24, 32, 48, 64, 128, 256, 512] {
    try render(icon, size: size, inset: 0, to: "elastos-\(size).png")
}

// The menu-bar icon is a template: macOS keeps only its alpha and tints it for light
// and dark menu bars. The mark alone, front layer solid and back layer half.
let paths = try NSRegularExpression(pattern: " d=\"([^\"]+)\"")
    .matches(in: svg, range: NSRange(svg.startIndex..., in: svg))
    .map { String(svg[Range($0.range(at: 1), in: svg)!]) }
guard paths.count >= 2 else {
    FileHandle.standardError.write("the SVG no longer has the two layers of the mark\n".data(using: .utf8)!)
    exit(1)
}
let template = """
<svg xmlns="http://www.w3.org/2000/svg" viewBox="-48 -154.5 794 794">
<path d="\(paths[0])" fill="#000" fill-opacity="0.5"/>
<path d="\(paths[1])" fill="#000"/>
</svg>
"""
try render(image(template), size: 36, inset: 0, to: "tray-template.png")
