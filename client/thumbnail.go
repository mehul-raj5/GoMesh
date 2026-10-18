package main

import (
	"bytes"
	common "common"
	"fmt"
	"image"
	_ "image/gif" // register GIF decoder
	"image/jpeg"
	_ "image/png" // register PNG decoder
	"strings"
)

// Thumbnail geometry. Two source pixels map to one terminal cell vertically
// (the ▀ half-block trick), so thumbHeight rows render as thumbHeight/2 lines.
const (
	thumbMaxW = 30
	thumbMaxH = 30
)

// renderThumbnail decodes a thumbnail JPEG and returns inline terminal art using
// unicode upper-half-blocks (▀): the top pixel colors the glyph foreground, the
// bottom pixel colors its background, giving two vertical pixels per cell.
// shrink scales img down, picking a source pixel for each cell, to fit maxW×maxH.
func shrink(img image.Image, maxW, maxH int) image.Image {
	b := img.Bounds()
	w, h := b.Dx(), b.Dy()
	if w <= maxW && h <= maxH {
		return img
	}
	tw, th := maxW, h*maxW/w
	if th > maxH {
		th, tw = maxH, w*maxH/h
	}
	tw, th = max(tw, 1), max(th, 1)
	dst := image.NewRGBA(image.Rect(0, 0, tw, th))
	for y := 0; y < th; y++ {
		for x := 0; x < tw; x++ {
			dst.Set(x, y, img.At(b.Min.X+x*w/tw, b.Min.Y+y*h/th))
		}
	}
	return dst
}

func renderThumbnail(thumb []byte) string {
	if len(thumb) == 0 {
		return ""
	}
	img, err := jpeg.Decode(bytes.NewReader(thumb))
	if err != nil {
		return ""
	}
	img = shrink(img, thumbMaxW, thumbMaxH) // the engine sends them bigger, for the apps

	b := img.Bounds()
	w, h := b.Dx(), b.Dy()
	var sb strings.Builder
	for y := 0; y < h; y += 2 {
		for x := 0; x < w; x++ {
			tr, tg, tb := rgbAt(img, b.Min.X+x, b.Min.Y+y)
			br, bg, bb := tr, tg, tb
			if y+1 < h {
				br, bg, bb = rgbAt(img, b.Min.X+x, b.Min.Y+y+1)
			}
			fmt.Fprintf(&sb, "\x1b[38;2;%d;%d;%dm\x1b[48;2;%d;%d;%dm▀", tr, tg, tb, br, bg, bb)
		}
		sb.WriteString("\x1b[0m")
		if y+2 < h {
			sb.WriteByte('\n')
		}
	}
	return sb.String()
}

func rgbAt(img image.Image, x, y int) (uint8, uint8, uint8) {
	r, g, b, _ := img.At(x, y).RGBA()
	return uint8(r >> 8), uint8(g >> 8), uint8(b >> 8)
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

func formatMediaLine(meta common.MediaMetadata) string {
	icon := "\U0001F4CE" // 📎
	if strings.HasPrefix(meta.FileType, "image/") {
		icon = "\U0001F5BC" // 🖼
	}
	return fmt.Sprintf("%s %s (%s, %s)", icon, meta.FileName, meta.FileType, humanSize(meta.FileSize))
}

func humanSize(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for x := n / unit; x >= unit; x /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGT"[exp])
}

// mediaMessage renders a received or sent file for the conversation pane, with
// its thumbnail drawn inline above the caption when there is one.
func mediaMessage(convID [16]byte, sender string, meta common.MediaMetadata) NetworkMsg {
	content := formatMediaLine(meta)
	if art := renderThumbnail(meta.Thumbnail); art != "" {
		// Leading newline so the art starts at column 0, below the "sender:" prefix.
		content = "\n" + art + "\n" + content
	}
	return NetworkMsg{ConversationID: convID, SenderName: sender, Content: content, IsFile: true}
}
