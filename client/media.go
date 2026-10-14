package main

import (
	"bytes"
	common "common"
	"crypto/rand"
	"fmt"
	"io"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// mediaHTTP is the client used to transfer encrypted blobs directly to/from
// Supabase Storage, bypassing the chat server.
var mediaHTTP = &http.Client{Timeout: 5 * time.Minute}

const urlRequestTimeout = 15 * time.Second

// detectMIME determines a file's MIME type from its extension, falling back to
// sniffing the leading bytes.
func detectMIME(name string, data []byte) string {
	if t := mime.TypeByExtension(strings.ToLower(filepath.Ext(name))); t != "" {
		if i := strings.IndexByte(t, ';'); i >= 0 {
			t = t[:i]
		}
		return t
	}
	if len(data) > 0 {
		return http.DetectContentType(data)
	}
	return "application/octet-stream"
}

// requestSignedURL sends a CtrlUpload/DownloadRq and blocks until the matching
// ack arrives (or times out). reqBody is nil for uploads.
func requestSignedURL(msgType uint8, convID [16]byte, reqBody []byte, want int) ([]string, error) {
	reqID := genID()
	ch := mgr.NewURLRequest(reqID)

	pkt := common.Packet{
		Header: common.Header{
			MsgType:        msgType,
			ConversationID: convID,
			MessageID:      reqID,
			SenderID:       mgr.UserID,
			BodyLen:        uint32(len(reqBody)),
		},
		Body: reqBody,
	}
	if err := sendPacket(&pkt); err != nil {
		mgr.CancelURLRequest(reqID)
		return nil, err
	}

	select {
	case strs := <-ch:
		if len(strs) < want {
			return nil, fmt.Errorf("server declined request (media storage may be unconfigured)")
		}
		return strs, nil
	case <-time.After(urlRequestTimeout):
		mgr.CancelURLRequest(reqID)
		return nil, fmt.Errorf("timeout waiting for signed URL")
	}
}

// progressReader wraps a reader and reports transfer progress to the TUI bar,
// throttled to whole-percent changes.
type progressReader struct {
	r       io.Reader
	total   int64
	read    int64
	lastPct int
}

func (p *progressReader) Read(b []byte) (int, error) {
	n, err := p.r.Read(b)
	p.read += int64(n)
	if p.total > 0 && program != nil {
		pct := int(float64(p.read) / float64(p.total) * 100)
		if pct != p.lastPct {
			p.lastPct = pct
			go program.Send(ProgressMsg(float64(p.read) / float64(p.total)))
		}
	}
	return n, err
}

// sendMedia encrypts a file, uploads the ciphertext to Supabase via a
// server-issued signed URL, then sends a lightweight E2E-encrypted metadata
// envelope through the chat server. Works for both 1-1 and group chats.
func sendMedia(convID [16]byte, path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		tuiPrintf("[ERROR] Cannot open file: %v", err)
		return
	}
	fileName := filepath.Base(path)
	fileType := detectMIME(fileName, data)
	hash := common.Sha256(data)

	var key [32]byte
	if _, err := io.ReadFull(rand.Reader, key[:]); err != nil {
		tuiPrintf("[ERROR] Key generation failed: %v", err)
		return
	}

	blob, err := common.Encrypt(key, data, nil)
	if err != nil {
		tuiPrintf("[ERROR] Encryption failed: %v", err)
		return
	}

	thumb := makeThumbnail(fileType, data)

	tuiPrintf("Requesting upload slot for %s (%d bytes)...", fileName, len(data))
	strs, err := requestSignedURL(common.CtrlUploadRq, convID, nil, 2)
	if err != nil {
		tuiPrintf("[ERROR] Upload permission denied: %v", err)
		return
	}
	objectPath, uploadURL := strs[0], strs[1]

	if err := httpPutBlob(uploadURL, fileType, blob); err != nil {
		tuiPrintf("[ERROR] Upload failed: %v", err)
		return
	}

	meta := common.MediaMetadata{
		FileName:   fileName,
		FileType:   fileType,
		FileSize:   int64(len(data)),
		ObjectPath: objectPath,
		DecryptKey: key,
		FileHash:   hash,
		Thumbnail:  thumb,
	}
	body := meta.Encode()

	pkt := common.Packet{
		Header: common.Header{
			MsgType:        common.MsgMediaMeta,
			ConversationID: convID,
			MessageID:      genID(),
			SenderID:       mgr.UserID,
			BodyLen:        uint32(len(body)),
		},
		Body: body,
	}

	if mgr.IsGroup(convID) {
		if encErr := sendGroupMessage(&pkt); encErr != nil {
			tuiPrintf("[ERROR] Group encryption failed for media: %v", encErr)
			return
		}
	} else {
		if encErr := sessionMgr.EncryptPacket(&pkt); encErr != nil {
			tuiPrintf("[ERROR] Encryption failed for media: %v", encErr)
			return
		}
		sendPacket(&pkt)
	}

	// Echo into the sender's own conversation pane.
	emitMediaMessage(convID, "You", meta)
	tuiPrintf("Media sent: %s", fileName)
}

// handleIncomingMedia is called from readLoop when a MsgMediaMeta envelope
// arrives. It shows the media inline immediately, then downloads and verifies
// the blob in the background.
func handleIncomingMedia(convID [16]byte, sender string, meta common.MediaMetadata) {
	emitMediaMessage(convID, sender, meta)
	go downloadAndVerify(meta)
}

// downloadAndVerify fetches the encrypted blob, decrypts it, checks the
// SHA-256, and saves it to downloads/. Integrity failures are dropped.
func downloadAndVerify(meta common.MediaMetadata) {
	reqBody := common.EncodeSignedURLPayload(meta.ObjectPath)
	// The conversation is derivable from the object path prefix; the server
	// re-checks membership, so we pass the convID via the request header.
	convID := convIDFromObjectPath(meta.ObjectPath)

	strs, err := requestSignedURL(common.CtrlDownloadRq, convID, reqBody, 1)
	if err != nil {
		tuiPrintf("[ERROR] Cannot fetch %s: %v", meta.FileName, err)
		return
	}
	downloadURL := strs[0]

	blob, err := httpGetBlob(downloadURL)
	if err != nil {
		tuiPrintf("[ERROR] Download failed for %s: %v", meta.FileName, err)
		return
	}

	plain, err := common.Decrypt(meta.DecryptKey, blob, nil)
	if err != nil {
		tuiPrintf("[ERROR] Decryption failed for %s: %v", meta.FileName, err)
		return
	}

	if common.Sha256(plain) != meta.FileHash {
		tuiPrintf("⚠ %s failed integrity check — dropped as corrupted/tampered", meta.FileName)
		return
	}

	savePath := saveDownload(meta.FileName, plain)
	tuiPrintf("✓ %s saved to %s", meta.FileName, savePath)
	if program != nil {
		go program.Send(ProgressMsg(1.0))
	}
}

// convIDFromObjectPath parses the "<convIDhex>/<random>" object path back into
// the conversation ID used to authorize the download.
func convIDFromObjectPath(objectPath string) [16]byte {
	var convID [16]byte
	if i := strings.IndexByte(objectPath, '/'); i == 32 {
		var raw []byte
		fmt.Sscanf(objectPath[:32], "%x", &raw)
		copy(convID[:], raw)
	}
	return convID
}

func httpPutBlob(url, contentType string, blob []byte) error {
	pr := &progressReader{r: bytes.NewReader(blob), total: int64(len(blob))}
	req, err := http.NewRequest(http.MethodPut, url, pr)
	if err != nil {
		return err
	}
	req.ContentLength = int64(len(blob))
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("x-upsert", "true")

	resp, err := mediaHTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("status %d: %s", resp.StatusCode, string(msg))
	}
	return nil
}

func httpGetBlob(url string) ([]byte, error) {
	resp, err := mediaHTTP.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("status %d: %s", resp.StatusCode, string(msg))
	}
	pr := &progressReader{r: resp.Body, total: resp.ContentLength}
	return io.ReadAll(pr)
}

// saveDownload writes plaintext to downloads/, avoiding collisions.
func saveDownload(fileName string, data []byte) string {
	dir := "downloads"
	os.MkdirAll(dir, 0755)
	path := filepath.Join(dir, fileName)
	if _, err := os.Stat(path); err == nil {
		var suffix [4]byte
		rand.Read(suffix[:])
		path += fmt.Sprintf(".%x", suffix)
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		tuiPrintf("[ERROR] Failed to save %s: %v", fileName, err)
	}
	return path
}
