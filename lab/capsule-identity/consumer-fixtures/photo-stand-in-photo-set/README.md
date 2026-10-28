# PH6 stand-in photo set

This test code stands in for the Runtime's launch by CID, which does not exist yet.

The three images were generated for this fixture from solid RGB colours. They
contain no downloaded artwork or personal data and use the repository's MIT
licence. Each is 4 × 4 pixels: `01.png` is (220, 40, 40), `02.jpg` is
(40, 180, 40), and `03.webp` is (40, 40, 220). PNG scanlines use filter 0,
8-bit RGB, Python's zlib compression, and standard IHDR/IDAT/IEND chunks.
The green PNG was encoded with `ffmpeg -frames:v 1 -q:v 2`; the blue PNG
with `cwebp -lossless`. The stand-in sentence is embedded as PNG tEXt,
JPEG COM, and WebP XMP metadata. The temporary PNG inputs were removed.

The source manifest pins the surface closure
`bafkreih2r3y7kst2gylz5miex5wptz2iqzfap2g53xmy27q2y6s6niurhe`, produced by
`capsule-bundle pack examples/photo-viewer/surface <physical-output-path>
--require photo-viewer=bafkreihxqbyijmoaykeixnnijvusmobqt2gpktqpu2r5ya2gbswitxvgym`.
That core CID came from packing the local photo core artifact with the same
tool. This pin identifies those bytes; a new build needs a newly packed viewer
and an explicit pin change. Tests create and pin their own temporary dependency
closures, so the checked-in pin is independent of their build paths.

Pack this folder with `capsule-bundle pack <physical-source-path>
<physical-output-path>`. The closure has exactly `capsule.json`, `images/01.png`,
`images/02.jpg`, and `images/03.webp`. This README is source provenance and stays
outside the closure. Slice 1 packs and resolves; it does not launch.
