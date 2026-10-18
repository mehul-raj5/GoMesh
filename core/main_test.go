package core

import (
	"fmt"
	"os"
	"testing"
)

// tcl is the client under test. Tests that drive the real client code use it;
// startClient replaces it with a fresh one, so no test inherits another's state.
var tcl *Client

// TestMain points the device's data directory at a temporary one. A test that
// signs a device out wipes its data directory, and it must never reach a
// developer's own files.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "gomesh-client-test")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	tcl = newClient()
	tcl.dataDir = dir
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}
