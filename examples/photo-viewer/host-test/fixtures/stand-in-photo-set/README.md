# PH6 stand-in photo set

This test code stands in for the Runtime's launch by CID, which does not exist yet.

The three images were generated for this fixture from solid RGB colours. They
contain no downloaded artwork or personal data and use the repository's MIT
licence. Each is 4 × 4 pixels: `01.png` is (220, 40, 40), `02.jpg` is
(40, 180, 40), and `03.webp` is (40, 40, 220). PNG scanlines use filter 0,
8-bit RGB, Python's zlib compression, and standard IHDR/IDAT/IEND chunks.
The green JPEG was encoded from its PNG with `ffmpeg -frames:v 1 -q:v 2`; the
blue WebP from its PNG with `cwebp -lossless`. The stand-in sentence is embedded as PNG tEXt,
JPEG COM, and WebP XMP metadata. The temporary PNG inputs were removed.

The source manifest pins the surface closure
`bafkreid5t2o74cs5wzpw4bht6q4zxe7fmma3pyg7tyraswtmv2sztsfbm4`, produced by
`capsule-bundle pack examples/photo-viewer/surface <physical-output-path>
--require photo-viewer=bafkreifvez4e7vxwurj25j6g243j6nu25zxnu673fkpbn75qq3ta6qjdhy`.
That core CID came from packing, with the same tool, the photo core's
reference artifact of `30f2619c` (sha256 `10812fc9…`, the recorded hash in
`examples/capsule-kit/repro/recorded-hashes.txt`). The same packing with the
earlier core CID gives the earlier pin, `bafkreih2r3y7…`. This pin identifies those bytes; a new build needs a newly packed viewer
and an explicit pin change. Tests create and pin their own temporary dependency
closures, so the checked-in pin is independent of their build paths.

Pack this folder with `capsule-bundle pack <physical-source-path>
<physical-output-path>`. The closure has exactly `capsule.json`, `images/01.png`,
`images/02.jpg`, and `images/03.webp`. This README is source provenance and stays
outside the closure. Slice 1 packs and resolves; it does not launch.
