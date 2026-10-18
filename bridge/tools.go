//go:build tools

// gomobile bind needs golang.org/x/mobile/bind in the module graph.
package bridge

import _ "golang.org/x/mobile/bind"
