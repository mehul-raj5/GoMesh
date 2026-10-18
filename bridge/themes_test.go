package bridge

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// The themes the app ships live in design/themes.json, which the app bundles
// as is. This checks them: all twenty-two, in the picker's order, every token a
// color, and every pairing of text and ground readable.

type themeFile struct {
	Version int `json:"version"`
	Themes  []struct {
		ID         string         `json:"id"`
		Name       string         `json:"name"`
		Appearance string         `json:"appearance"`
		Source     string         `json:"source"`
		Notes      []string       `json:"notes"`
		Colors     map[string]any `json:"colors"`
	} `json:"themes"`
}

var themeTokens = []string{"bg", "surface", "surfaceRaised", "border", "text", "textMuted", "accent", "accentText", "onAccent",
	"bubbleOut", "onBubbleOut", "bubbleIn", "onBubbleIn", "danger", "warning", "success"}

// optionalTokens may be left out of a theme; the app then draws with the token
// named here instead (Theme.swift keeps the same table). The test checks a theme
// as drawn, so it resolves each one the same way.
var optionalTokens = map[string]string{
	"chatBg":        "bg",
	"chatPattern":   "textMuted", // decorative: dots, not text, so no contrast pair
	"selectedRow":   "accent",
	"onSelectedRow": "onAccent",
	"metaOut":       "onBubbleOut",
	"metaIn":        "onBubbleIn",
	"tickRead":      "onBubbleOut",
}

var hexColor = regexp.MustCompile(`^#[0-9a-f]{6}$`)

func luminance(hex string) float64 {
	var c [3]float64
	for i := range c {
		v, _ := strconv.ParseUint(hex[1+2*i:3+2*i], 16, 8)
		s := float64(v) / 255
		if s <= 0.04045 {
			c[i] = s / 12.92
		} else {
			c[i] = math.Pow((s+0.055)/1.055, 2.4)
		}
	}
	return 0.2126*c[0] + 0.7152*c[1] + 0.0722*c[2]
}

// blendHex is top at alpha over under, as the app draws a translucent fill.
func blendHex(top, under string, alpha float64) string {
	ch := func(h string, i int) float64 { v, _ := strconv.ParseUint(h[1+2*i:3+2*i], 16, 8); return float64(v) }
	out := "#"
	for i := 0; i < 3; i++ {
		out += fmt.Sprintf("%02x", int(math.Round(alpha*ch(top, i)+(1-alpha)*ch(under, i))))
	}
	return out
}

func contrastRatio(a, b string) float64 {
	la, lb := luminance(a), luminance(b)
	if la < lb {
		la, lb = lb, la
	}
	return (la + 0.05) / (lb + 0.05)
}

func TestThemes(t *testing.T) {
	data, err := os.ReadFile("../design/themes.json")
	if err != nil {
		t.Fatal(err)
	}
	var f themeFile
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatal(err)
	}
	if f.Version != 1 {
		t.Fatalf("version %d", f.Version)
	}

	var light, dark []string
	ids := map[string]bool{}
	for _, th := range f.Themes {
		if ids[th.ID] || th.ID == "" || th.ID == "auto" {
			t.Errorf("theme ID %q is empty, reserved or repeated", th.ID)
		}
		ids[th.ID] = true
		switch th.Appearance {
		case "light":
			light = append(light, th.Name)
		case "dark":
			dark = append(dark, th.Name)
		default:
			t.Errorf("%s: appearance %q", th.Name, th.Appearance)
		}
		if th.Source != "original" && !strings.Contains(th.Source, "github.com/") && !strings.Contains(th.Source, "npmjs.com/") {
			t.Errorf("%s: its source %q is not a published palette", th.Name, th.Source)
		}

		c := map[string]string{}
		for _, tok := range themeTokens {
			s, _ := th.Colors[tok].(string)
			if !hexColor.MatchString(s) {
				t.Errorf("%s: %s is %q, not #rrggbb", th.Name, tok, s)
				continue
			}
			c[tok] = s
		}
		lists := map[string][]string{}
		for _, key := range []string{"palette", "paletteText"} {
			raw, _ := th.Colors[key].([]any)
			if len(raw) != 8 {
				t.Errorf("%s: %s has %d colors, not 8", th.Name, key, len(raw))
			}
			for i, p := range raw {
				s, _ := p.(string)
				if !hexColor.MatchString(s) {
					t.Errorf("%s: %s[%d] is %q", th.Name, key, i, s)
				}
				lists[key] = append(lists[key], s)
			}
		}
		for tok := range th.Colors {
			_, optional := optionalTokens[tok]
			if !slices.Contains(themeTokens, tok) && !optional && tok != "palette" && tok != "paletteText" {
				t.Errorf("%s: unknown token %q; the app ignores it, so it is a mistake", th.Name, tok)
			}
		}
		if len(c) != len(themeTokens) {
			continue
		}
		// An optional token is a color if set, else what the app falls back to.
		for tok, fallback := range optionalTokens {
			raw, set := th.Colors[tok]
			if !set {
				c[tok] = c[fallback]
				continue
			}
			s, _ := raw.(string)
			if !hexColor.MatchString(s) {
				t.Errorf("%s: %s is %q, not #rrggbb", th.Name, tok, s)
				c[tok] = c[fallback]
				continue
			}
			c[tok] = s
		}

		if (th.Appearance == "light") != (luminance(c["bg"]) > luminance(c["text"])) {
			t.Errorf("%s: a %s theme with a background of %s and text of %s", th.Name, th.Appearance, c["bg"], c["text"])
		}
		// Every pair the screens draw. Text is held to 4.5:1 however small it
		// is drawn: a bubble's timestamps are metaOut or metaIn, held to it, and
		// never a faded text colour. Warning and success colour icons and
		// dots, not text, so 3:1.
		for _, pair := range []struct {
			fg, bg string
			min    float64
		}{
			{"text", "bg", 4.5}, {"text", "surface", 4.5}, {"text", "surfaceRaised", 4.5},
			{"textMuted", "bg", 4.5}, {"textMuted", "surface", 4.5}, {"textMuted", "surfaceRaised", 4.5},
			{"accentText", "bg", 4.5}, {"accentText", "surface", 4.5},
			{"onAccent", "accent", 4.5},
			{"onBubbleOut", "bubbleOut", 4.5}, {"onBubbleIn", "bubbleIn", 4.5},
			{"danger", "bg", 4.5}, {"danger", "surface", 4.5}, {"warning", "bg", 3}, {"success", "bg", 3},
		} {
			if r := contrastRatio(c[pair.fg], c[pair.bg]); r < pair.min {
				t.Errorf("%s: %s on %s is %.2f:1, under %.1f:1", th.Name, pair.fg, pair.bg, r, pair.min)
			}
		}
		// Sender names on the incoming bubble, and an avatar's letter on its wash:
		// the palette colour at 22% over the surface or background it sits on.
		if len(lists["palette"]) == 8 && len(lists["paletteText"]) == 8 {
			for i, name := range lists["paletteText"] {
				if r := contrastRatio(name, c["bubbleIn"]); r < 4.5 {
					t.Errorf("%s: paletteText[%d] on bubbleIn is %.2f:1", th.Name, i, r)
				}
				for _, ground := range []string{"surface", "bg"} {
					wash := blendHex(lists["palette"][i], c[ground], 0.22)
					if r := contrastRatio(name, wash); r < 3 {
						t.Errorf("%s: paletteText[%d] on its wash over %s is %.2f:1", th.Name, i, ground, r)
					}
				}
			}
		}
	}

	wantLight := []string{"Telegram Light", "GoMesh Light", "Paper", "Catppuccin Latte", "One Light", "Gruvbox Light",
		"Solarized Light", "Rosé Pine Dawn", "GitHub Light"}
	wantDark := []string{"Telegram Dark", "GoMesh Dark", "Catppuccin Mocha", "Catppuccin Macchiato", "One Dark", "Gruvbox Dark",
		"Dracula", "Nord", "Tokyo Night", "Solarized Dark", "Rosé Pine", "Rosé Pine Moon", "GitHub Dark"}
	if !slices.Equal(light, wantLight) {
		t.Errorf("light themes, in order: %q", light)
	}
	if !slices.Equal(dark, wantDark) {
		t.Errorf("dark themes, in order: %q", dark)
	}
}

func TestContrastRatio(t *testing.T) {
	if r := contrastRatio("#000000", "#ffffff"); math.Abs(r-21) > 0.01 {
		t.Fatalf("black on white: %.2f", r)
	}
	if r := contrastRatio("#777777", "#ffffff"); math.Abs(r-4.48) > 0.01 { // the well-known near miss
		t.Fatalf("#777 on white: %.2f", r)
	}
}
