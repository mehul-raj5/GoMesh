package core

import (
	"bytes"
	common "common"
	"image"
	"image/color"
	_ "image/gif" // register GIF decoder
	"image/jpeg"
	_ "image/png" // register PNG decoder
	"strings"
	"time"
)

// Thumbnail geometry: big enough for a chat bubble on a phone, small enough to
// travel inside the message envelope. The terminal client scales it down again
// for its half-block preview.
const (
	thumbMaxW = 320
	thumbMaxH = 320
)

// makeThumbnail returns a small JPEG preview for image files, or nil for
// non-images / on failure. Uses only the standard library (an area-averaging
// downscale) so no image-resize dependency is required.
func makeThumbnail(fileType string, data []byte) []byte {
	if !strings.HasPrefix(fileType, "image/") {
		return nil
	}
	src, _, err := image.Decode(bytes.NewReader(data))
	if err != nil {
		return nil
	}

	b := src.Bounds()
	tw, th := scaleToFit(b.Dx(), b.Dy(), thumbMaxW, thumbMaxH)
	small := resizeArea(src, tw, th)

	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, small, &jpeg.Options{Quality: 60}); err != nil {
		return nil
	}
	return buf.Bytes()
}

// scaleToFit returns the largest w×h (preserving aspect ratio) that fits within
// maxW×maxH; never upscales.
func scaleToFit(w, h, maxW, maxH int) (int, int) {
	if w <= 0 || h <= 0 {
		return 1, 1
	}
	if w <= maxW && h <= maxH {
		return w, h
	}
	tw := maxW
	th := h * maxW / w
	if th > maxH {
		th = maxH
		tw = w * maxH / h
	}
	if tw < 1 {
		tw = 1
	}
	if th < 1 {
		th = 1
	}
	return tw, th
}

// resizeNearest downscales src to tw×th using nearest-neighbor sampling.
// resizeArea scales src down to tw×th, each target pixel the average of the
// source pixels it covers, which keeps a photo smooth where picking one source
// pixel per target would alias.
func resizeArea(src image.Image, tw, th int) *image.RGBA {
	dst := image.NewRGBA(image.Rect(0, 0, tw, th))
	b := src.Bounds()
	for y := 0; y < th; y++ {
		y0, y1 := b.Min.Y+y*b.Dy()/th, b.Min.Y+(y+1)*b.Dy()/th
		if y1 <= y0 {
			y1 = y0 + 1
		}
		for x := 0; x < tw; x++ {
			x0, x1 := b.Min.X+x*b.Dx()/tw, b.Min.X+(x+1)*b.Dx()/tw
			if x1 <= x0 {
				x1 = x0 + 1
			}
			var r, g, bl, a, n uint64
			for sy := y0; sy < y1; sy++ {
				for sx := x0; sx < x1; sx++ {
					cr, cg, cb, ca := src.At(sx, sy).RGBA()
					r, g, bl, a, n = r+uint64(cr), g+uint64(cg), bl+uint64(cb), a+uint64(ca), n+1
				}
			}
			dst.Set(x, y, color.RGBA64{uint16(r / n), uint16(g / n), uint16(bl / n), uint16(a / n)})
		}
	}
	return dst
}

// emitMediaMessage reports a received or sent file as a message, with its
// metadata (thumbnail included) for the host to show.
func (cl *Client) emitMediaMessage(convID [16]byte, sender string, meta common.MediaMetadata) {
	m := meta
	cl.emit(Event{Kind: EventMessage, ConvID: convID, SenderName: sender, Media: &m, Time: time.Now()})
}
