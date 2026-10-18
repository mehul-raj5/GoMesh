package core

import (
	"bytes"
	common "common"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"log"
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
func (cl *Client) requestSignedURL(msgType uint8, convID [16]byte, reqBody []byte, want int) ([]string, error) {
	reqID := genID()
	ch := cl.mgr.NewURLRequest(reqID)

	pkt := common.Packet{
		Header: common.Header{
			MsgType:        msgType,
			ConversationID: convID,
			MessageID:      reqID,
			SenderID:       cl.mgr.UserID,
			BodyLen:        uint32(len(reqBody)),
		},
		Body: reqBody,
	}
	if err := cl.sendPacket(&pkt); err != nil {
		cl.mgr.CancelURLRequest(reqID)
		return nil, err
	}

	select {
	case strs := <-ch:
		if len(strs) < want {
			return nil, fmt.Errorf("server declined request (media storage may be unconfigured)")
		}
		return strs, nil
	case <-time.After(urlRequestTimeout):
		cl.mgr.CancelURLRequest(reqID)
		return nil, fmt.Errorf("timeout waiting for signed URL")
	}
}

// A transfer is one file going out or coming in, as the host follows it.
type transfer struct {
	cl     *Client
	id     string
	conv   [16]byte
	name   string
	sender [16]byte // set for a file coming in
}

func newTransfer(cl *Client, conv [16]byte, name string, sender [16]byte) *transfer {
	id := genID()
	return &transfer{cl: cl, id: hex.EncodeToString(id[:8]), conv: conv, name: name, sender: sender}
}

func (t *transfer) report(p float64) {
	t.cl.emit(Event{Kind: EventProgress, ConvID: t.conv, Transfer: t.id, Text: t.name, Sender: t.sender, Progress: p})
}

func (t *transfer) done()   { t.report(1) }
func (t *transfer) failed() { t.report(-1) }

// progressReader wraps a reader and reports transfer progress to the TUI bar,
// throttled to whole-percent changes.
type progressReader struct {
	r       io.Reader
	total   int64
	read    int64
	lastPct int
	report  func(float64)
}

func (p *progressReader) Read(b []byte) (int, error) {
	n, err := p.r.Read(b)
	p.read += int64(n)
	if p.total > 0 {
		pct := int(float64(p.read) / float64(p.total) * 100)
		if pct != p.lastPct {
			p.lastPct = pct
			if p.report != nil {
				p.report(float64(p.read) / float64(p.total))
			}
		}
	}
	return n, err
}

// sendMedia encrypts a file, uploads the ciphertext to Supabase via a
// server-issued signed URL, then sends a lightweight E2E-encrypted metadata
// envelope through the chat server. Works for both 1-1 and group chats.
func (cl *Client) sendMedia(convID [16]byte, path string, t *transfer) {
	data, err := os.ReadFile(path)
	if err != nil {
		cl.notify(LevelError, "Cannot open file: %v", err)
		t.failed()
		return
	}
	fileName := filepath.Base(path)
	fileType := detectMIME(fileName, data)
	hash := common.Sha256(data)

	var key [32]byte
	if _, err := io.ReadFull(rand.Reader, key[:]); err != nil {
		cl.notify(LevelError, "Key generation failed: %v", err)
		t.failed()
		return
	}

	blob, err := common.Encrypt(key, data, nil)
	if err != nil {
		cl.notify(LevelError, "Encryption failed: %v", err)
		t.failed()
		return
	}

	thumb := makeThumbnail(fileType, data)

	cl.notify(LevelInfo, "Requesting upload slot for %s (%d bytes)...", fileName, len(data))
	strs, err := cl.requestSignedURL(common.CtrlUploadRq, convID, nil, 2)
	if err != nil {
		cl.notify(LevelError, "Upload permission denied: %v", err)
		t.failed()
		return
	}
	objectPath, uploadURL := strs[0], strs[1]

	if err := httpPutBlob(uploadURL, fileType, blob, t.report); err != nil {
		cl.notify(LevelError, "Upload failed: %v", err)
		t.failed()
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
			SenderID:       cl.mgr.UserID,
			BodyLen:        uint32(len(body)),
		},
		Body: body,
	}

	// The sender keeps a copy, sealed, like any file it receives.
	ref := &MediaRef{FileName: fileName, FileType: fileType, Size: int64(len(data)), Thumbnail: thumb}
	if h := cl.myHistory; h != nil {
		if id, err := h.storeMedia(data); err == nil {
			ref.LocalID = id
		} else {
			log.Printf("[ERROR] could not keep a copy of %s: %v", fileName, err)
		}
	}
	msg := HistoryMessage{Sender: cl.mgr.UserID, SenderName: cl.mgr.Username, Outgoing: true, Time: time.Now(), Media: ref,
		MsgID: pkt.Header.MessageID, Recipients: cl.recipientsOf(convID)}

	queued := false
	if cl.mgr.IsGroup(convID) {
		queued, err = cl.sendGroupMessage(&pkt, func() int64 {
			m := msg
			m.Status = StatusQueued
			return cl.recordSeq(convID, m)
		})
	} else if err = cl.sessionMgr.EncryptPacket(&pkt); err == nil {
		err = cl.sendPacket(&pkt)
	}
	if err != nil {
		// Uploaded but not announced: nobody can fetch it. Kept as failed, so the
		// chat shows it did not go.
		msg.Status = StatusFailed
		cl.record(convID, msg)
		cl.notify(LevelError, "Could not send %s: %v", fileName, err)
		t.failed()
		return
	}
	// Echo into the sender's own conversation pane.
	cl.emitMediaMessage(convID, "You", meta)
	if !queued {
		cl.record(convID, msg)
	}
	t.done()
	cl.notify(LevelInfo, "Media sent: %s", fileName)
}

// handleIncomingMedia is called from readLoop when a MsgMediaMeta envelope
// arrives. It shows the media inline immediately, then downloads and verifies
// the blob in the background.
func (cl *Client) handleIncomingMedia(convID, senderID, msgID [16]byte, sender string, meta common.MediaMetadata) {
	cl.emitMediaMessage(convID, sender, meta)
	t := newTransfer(cl, convID, meta.FileName, senderID)
	go cl.downloadAndVerify(convID, senderID, msgID, sender, meta, t)
}

// downloadAndVerify fetches the encrypted blob, decrypts it, checks the
// SHA-256, and saves it to downloads/. Integrity failures are dropped.
func (cl *Client) downloadAndVerify(msgConv, senderID, msgID [16]byte, sender string, meta common.MediaMetadata, t *transfer) {
	reqBody := common.EncodeSignedURLPayload(meta.ObjectPath)
	// The conversation is derivable from the object path prefix; the server
	// re-checks membership, so we pass the convID via the request header.
	convID := convIDFromObjectPath(meta.ObjectPath)

	strs, err := cl.requestSignedURL(common.CtrlDownloadRq, convID, reqBody, 1)
	if err != nil {
		cl.systemLine(msgConv, LevelError, "Could not fetch %s from %s: %v", meta.FileName, sender, err)
		t.failed()
		return
	}
	downloadURL := strs[0]

	blob, err := httpGetBlob(downloadURL, t.report)
	if err != nil {
		cl.systemLine(msgConv, LevelError, "Could not download %s from %s: %v", meta.FileName, sender, err)
		t.failed()
		return
	}

	plain, err := common.Decrypt(meta.DecryptKey, blob, nil)
	if err != nil {
		cl.systemLine(msgConv, LevelError, "%s from %s could not be decrypted: %v", meta.FileName, sender, err)
		t.failed()
		return
	}

	if common.Sha256(plain) != meta.FileHash {
		cl.systemLine(msgConv, LevelWarn, "%s from %s was altered on the way, so it was dropped.", meta.FileName, sender)
		t.failed()
		return
	}

	// The file is kept sealed, under a random name, and recorded in the history.
	ref := &MediaRef{FileName: meta.FileName, FileType: meta.FileType, Size: meta.FileSize, Thumbnail: meta.Thumbnail}
	if h := cl.myHistory; h != nil {
		id, err := h.storeMedia(plain)
		if err != nil {
			log.Printf("[ERROR] could not keep %s: %v", meta.FileName, err)
			cl.notify(LevelError, "Could not keep %s: %v", meta.FileName, err)
		}
		ref.LocalID = id
	}
	cl.record(msgConv, HistoryMessage{Sender: senderID, SenderName: sender, Time: time.Now(), Media: ref, MsgID: msgID})
	t.done()
	if ref.LocalID != "" {
		cl.emit(Event{Kind: EventMediaSaved, ConvID: msgConv, SenderName: sender, Text: meta.FileName, MediaID: ref.LocalID})
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

func httpPutBlob(url, contentType string, blob []byte, report func(float64)) error {
	pr := &progressReader{r: bytes.NewReader(blob), total: int64(len(blob)), report: report}
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

func httpGetBlob(url string, report func(float64)) ([]byte, error) {
	resp, err := mediaHTTP.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("status %d: %s", resp.StatusCode, string(msg))
	}
	pr := &progressReader{r: resp.Body, total: resp.ContentLength, report: report}
	return io.ReadAll(pr)
}
