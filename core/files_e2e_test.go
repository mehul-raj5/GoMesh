package core

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"image"
	"image/color"
	"image/png"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// fakeStorage stands in for Supabase Storage, answering the four calls the
// server and clients make, with the shapes server/supabase.go reads: a
// relative "url" from signing an upload, a relative "signedURL" from signing a
// download, and the token in the query string.
type fakeStorage struct {
	*httptest.Server
	mu          sync.Mutex
	objects     map[string][]byte
	tokens      map[string]string // token -> object path
	failUploads bool
}

const fakeBucket = "gomesh-media"
const fakeKey = "test-service-key"

func newFakeStorage(t *testing.T) *fakeStorage {
	t.Helper()
	f := &fakeStorage{objects: map[string][]byte{}, tokens: map[string]string{}}
	mux := http.NewServeMux()
	signUpload := "/storage/v1/object/upload/sign/" + fakeBucket + "/"
	signDownload := "/storage/v1/object/sign/" + fakeBucket + "/"
	mux.HandleFunc(signUpload, func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, signUpload)
		switch r.Method {
		case http.MethodPost: // the server asks to sign an upload
			if r.Header.Get("Authorization") != "Bearer "+fakeKey {
				http.Error(w, "no key", http.StatusUnauthorized)
				return
			}
			tok := f.token(path)
			json.NewEncoder(w).Encode(map[string]string{"url": "/object/upload/sign/" + fakeBucket + "/" + path + "?token=" + tok})
		case http.MethodPut: // a client uploads with the token
			f.mu.Lock()
			fail := f.failUploads
			f.mu.Unlock()
			if fail {
				http.Error(w, "storage is down", http.StatusServiceUnavailable)
				return
			}
			if !f.valid(r.URL.Query().Get("token"), path) {
				http.Error(w, "bad token", http.StatusForbidden)
				return
			}
			b, _ := io.ReadAll(r.Body)
			f.mu.Lock()
			f.objects[path] = b
			f.mu.Unlock()
			w.Write([]byte(`{"Key":"ok"}`))
		default:
			http.Error(w, "method", http.StatusMethodNotAllowed)
		}
	})
	mux.HandleFunc(signDownload, func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, signDownload)
		switch r.Method {
		case http.MethodPost:
			if r.Header.Get("Authorization") != "Bearer "+fakeKey {
				http.Error(w, "no key", http.StatusUnauthorized)
				return
			}
			tok := f.token(path)
			json.NewEncoder(w).Encode(map[string]string{"signedURL": "/object/sign/" + fakeBucket + "/" + path + "?token=" + tok})
		case http.MethodGet:
			if !f.valid(r.URL.Query().Get("token"), path) {
				http.Error(w, "bad token", http.StatusForbidden)
				return
			}
			f.mu.Lock()
			b, ok := f.objects[path]
			f.mu.Unlock()
			if !ok {
				http.NotFound(w, r)
				return
			}
			w.Write(b)
		default:
			http.Error(w, "method", http.StatusMethodNotAllowed)
		}
	})
	f.Server = httptest.NewServer(mux)
	t.Cleanup(f.Close)
	return f
}

func (f *fakeStorage) token(path string) string {
	b := make([]byte, 12)
	rand.Read(b)
	tok := hex.EncodeToString(b)
	f.mu.Lock()
	f.tokens[tok] = path
	f.mu.Unlock()
	return tok
}

func (f *fakeStorage) valid(tok, path string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return tok != "" && f.tokens[tok] == path
}

func (f *fakeStorage) env() []string {
	return []string{"SUPABASE_URL=" + f.URL, "SUPABASE_SERVICE_KEY=" + fakeKey, "SUPABASE_BUCKET=" + fakeBucket}
}

func pngFile(t *testing.T, dir string) (string, []byte) {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, 64, 48))
	for x := 0; x < 64; x++ {
		for y := 0; y < 48; y++ {
			img.Set(x, y, color.RGBA{uint8(x * 4), uint8(y * 5), 200, 255})
		}
	}
	var b bytes.Buffer
	png.Encode(&b, img)
	path := filepath.Join(dir, "sunset.png")
	os.WriteFile(path, b.Bytes(), 0o600)
	return path, b.Bytes()
}

// A file goes from one app to another through the storage: the transfer is
// followed by its ID in its chat, both sides keep it sealed with a thumbnail,
// and what comes out is what went in. Its contents never reach the storage.
func TestFilesEndToEnd(t *testing.T) {
	store := newFakeStorage(t)
	srv := startServerProc(t, store.env()...)
	alice, aliceRec := signedInClient(t, srv.addr, "alice")
	bob, bobRec := signedInClient(t, srv.addr, "bob")
	conv, err := alice.OpenChat("bob")
	if err != nil {
		t.Fatal(err)
	}
	if err := alice.SendText(conv, "a photo is coming"); err != nil {
		t.Fatal(err)
	}
	eventually(t, "bob has the chat", keptText(bob, conv, "a photo is coming"))

	dir := t.TempDir()
	big := filepath.Join(dir, "huge.bin")
	f, _ := os.Create(big)
	f.Truncate(MaxFileSize + 1)
	f.Close()
	if _, err := alice.SendFile(conv, big); !errors.Is(err, ErrFileTooLarge) {
		t.Fatalf("an oversized file: %v", err)
	}

	path, data := pngFile(t, dir)
	n := aliceRec.count()
	m := bobRec.count()
	transfer, err := alice.SendFile(conv, path)
	if err != nil || transfer == "" {
		t.Fatalf("sending: %q %v", transfer, err)
	}
	aliceRec.waitFor(t, "the upload finishing", n, func(ev Event) bool {
		return ev.Kind == EventProgress && ev.Transfer == transfer && ev.ConvID == conv && ev.Progress == 1 && ev.Text == "sunset.png"
	})
	saved := bobRec.waitFor(t, "bob keeping it", m, func(ev Event) bool { return ev.Kind == EventMediaSaved && ev.ConvID == conv })
	_ = saved
	bobRec.waitFor(t, "bob's download finishing", m, func(ev Event) bool {
		return ev.Kind == EventProgress && ev.ConvID == conv && ev.Progress == 1 && ev.Sender == alice.UserID()
	})

	check := func(who *Client, outgoing bool) {
		t.Helper()
		msgs, err := who.HistoryMessages(who.UserID(), conv, 0, 10)
		if err != nil {
			t.Fatal(err)
		}
		last := msgs[len(msgs)-1]
		if last.Media == nil || last.Outgoing != outgoing || last.Media.FileName != "sunset.png" || last.Media.LocalID == "" ||
			len(last.Media.Thumbnail) == 0 || last.Media.Size != int64(len(data)) || last.Status != StatusSent {
			t.Fatalf("kept: %+v", last)
		}
		out, err := who.ExportMedia(who.UserID(), last.Media.LocalID, last.Media.FileName, t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		if got, _ := os.ReadFile(out); !bytes.Equal(got, data) {
			t.Fatal("the exported file differs from the one sent")
		}
	}
	check(alice, true)
	check(bob, false)

	list, _ := bob.ChatList()
	if len(list) != 1 || !list[0].PreviewIsFile || list[0].Preview != "sunset.png" {
		t.Fatalf("bob's chat list: %+v", list)
	}

	store.mu.Lock()
	defer store.mu.Unlock()
	if len(store.objects) != 1 {
		t.Fatalf("%d objects stored", len(store.objects))
	}
	for _, b := range store.objects {
		if bytes.Contains(b, data[:32]) || bytes.Equal(b, data) {
			t.Fatal("the storage holds the file in the clear")
		}
	}
}

// An upload the storage refuses is reported as failed, by its transfer, and
// nothing is kept as sent.
func TestAFailedUploadSaysSo(t *testing.T) {
	store := newFakeStorage(t)
	store.failUploads = true
	srv := startServerProc(t, store.env()...)
	alice, rec := signedInClient(t, srv.addr, "alice")
	bob := dialParty(t, srv.addr, "bob")
	_ = bob
	conv, err := alice.OpenChat("bob")
	if err != nil {
		t.Fatal(err)
	}
	path, _ := pngFile(t, t.TempDir())
	n := rec.count()
	transfer, err := alice.SendFile(conv, path)
	if err != nil {
		t.Fatal(err)
	}
	rec.waitFor(t, "the failure", n, func(ev Event) bool {
		return ev.Kind == EventProgress && ev.Transfer == transfer && ev.Progress == -1
	})
	msgs, _ := alice.HistoryMessages(alice.UserID(), conv, 0, 10)
	for _, m := range msgs {
		if m.Media != nil && m.Status == StatusSent {
			t.Fatalf("a file that never went is kept as sent: %+v", m)
		}
	}
}
