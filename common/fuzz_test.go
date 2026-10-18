package common

import (
	"bytes"
	"testing"
)

// Every decoder here runs on bytes an attacker controls, before any
// authentication has happened. None of them may panic, and any input one
// accepts must survive a re-encode unchanged.

func FuzzDecodeConvInfo(f *testing.F) {
	f.Add((&ConvInfo{}).Encode())
	f.Add((&ConvInfo{
		ConvID:  [IDSize]byte{1},
		IsGroup: true,
		Name:    "g",
		Members: []ConvMember{{UserID: [IDSize]byte{2}, PubKey: [32]byte{3}, Name: "alice"}},
	}).Encode())
	f.Add([]byte{})
	f.Add(bytes.Repeat([]byte{0xFF}, 64))

	f.Fuzz(func(t *testing.T, data []byte) {
		got, err := DecodeConvInfo(data)
		if err != nil {
			return
		}
		again, err := DecodeConvInfo(got.Encode())
		if err != nil {
			t.Fatalf("re-decoding an accepted value failed: %v", err)
		}
		if again.ConvID != got.ConvID || again.IsGroup != got.IsGroup || again.Name != got.Name {
			t.Fatalf("round trip changed the header:\n got %+v\nwant %+v", again, got)
		}
		if len(again.Members) != len(got.Members) {
			t.Fatalf("round trip changed member count: %d vs %d", len(again.Members), len(got.Members))
		}
		for i := range got.Members {
			if again.Members[i] != got.Members[i] {
				t.Fatalf("round trip changed member %d", i)
			}
		}
	})
}

func FuzzDecodeSenderKeyDist(f *testing.F) {
	f.Add((&SenderKeyDist{}).Encode())
	f.Add((&SenderKeyDist{GroupID: [IDSize]byte{1}, KeyID: 9, ChainKey: [32]byte{2}, N: 4}).Encode())
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		got, err := DecodeSenderKeyDist(data)
		if err != nil {
			return
		}
		again, err := DecodeSenderKeyDist(got.Encode())
		if err != nil {
			t.Fatalf("re-decoding an accepted value failed: %v", err)
		}
		if again != got {
			t.Fatalf("round trip changed the payload:\n got %+v\nwant %+v", again, got)
		}
	})
}

func FuzzDecodeSignedChange(f *testing.F) {
	sc := SignedChange{Change: GroupChange{
		GroupID: [IDSize]byte{1}, Version: 1, Action: ActionCreate, Actor: [IDSize]byte{2},
		Targets: []MemberKey{{ID: [IDSize]byte{2}, IdentityKey: [32]byte{3}, SigningKey: [32]byte{4}}},
	}}
	f.Add(sc.Encode())
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		got, n, err := DecodeSignedChange(data)
		if err != nil {
			return
		}
		again, m, err := DecodeSignedChange(got.Encode())
		if err != nil || m != n {
			t.Fatalf("re-decoding an accepted value failed: %v (%d vs %d)", err, m, n)
		}
		if again.Hash() != got.Hash() {
			t.Fatal("round trip changed the change")
		}
	})
}

func FuzzDecodeGroupWire(f *testing.F) {
	w := GroupWire{Header: GroupHeader{Version: GroupMsgVersion, KeyID: 1}, Ciphertext: make([]byte, NonceSize+16)}
	f.Add(w.Encode())
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		got, err := DecodeGroupWire(data)
		if err != nil {
			return
		}
		again, err := DecodeGroupWire(got.Encode())
		if err != nil {
			t.Fatalf("re-decoding an accepted value failed: %v", err)
		}
		if again.Header != got.Header || again.Signature != got.Signature || string(again.Ciphertext) != string(got.Ciphertext) {
			t.Fatal("round trip changed the message")
		}
	})
}

func FuzzDecodeGroupChangeBody(f *testing.F) {
	f.Add([]byte{})
	f.Add((&GroupChangeBody{Name: "g"}).Encode())

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = DecodeGroupChangeBody(data)
		_, _, _ = DecodeGroupHints(data)
		_, _ = DecodeGroupChangeReject(data)
		_, _ = DecodeUserLookup(data)
	})
}

func FuzzDecodeMediaMetadata(f *testing.F) {
	f.Add((&MediaMetadata{}).Encode())
	f.Add((&MediaMetadata{
		FileName: "a.png", FileType: "image/png", FileSize: 12,
		ObjectPath: "p", Thumbnail: []byte{1, 2, 3},
	}).Encode())
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		got, err := DecodeMediaMetadata(data)
		if err != nil {
			return
		}
		again, err := DecodeMediaMetadata(got.Encode())
		if err != nil {
			t.Fatalf("re-decoding an accepted value failed: %v", err)
		}
		if again.FileName != got.FileName || again.FileType != got.FileType ||
			again.FileSize != got.FileSize || again.ObjectPath != got.ObjectPath ||
			again.DecryptKey != got.DecryptKey || again.FileHash != got.FileHash ||
			!bytes.Equal(again.Thumbnail, got.Thumbnail) {
			t.Fatalf("round trip changed the metadata:\n got %+v\nwant %+v", again, got)
		}
	})
}

func FuzzDecodeSignedURLPayload(f *testing.F) {
	f.Add(EncodeSignedURLPayload("a", "b"), 2)
	f.Add([]byte{}, 1)
	f.Add(bytes.Repeat([]byte{0xFF}, 16), 3)

	f.Fuzz(func(t *testing.T, data []byte, count int) {
		if count < 0 || count > 8 {
			return
		}
		got, err := DecodeSignedURLPayload(data, count)
		if err != nil {
			return
		}
		if len(got) != count {
			t.Fatalf("asked for %d strings, got %d", count, len(got))
		}
		again, err := DecodeSignedURLPayload(EncodeSignedURLPayload(got...), count)
		if err != nil {
			t.Fatalf("re-decoding an accepted value failed: %v", err)
		}
		for i := range got {
			if again[i] != got[i] {
				t.Fatalf("round trip changed string %d", i)
			}
		}
	})
}

// Decode reads straight off the socket, so it is the very first thing to touch
// hostile bytes.
func FuzzDecodePacket(f *testing.F) {
	var buf bytes.Buffer
	(&Packet{Header: Header{MsgType: MsgText, BodyLen: 3}, Body: []byte("abc")}).Encode(&buf)
	f.Add(buf.Bytes())
	f.Add(make([]byte, HeaderSize))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		pkt, err := Decode(bytes.NewReader(data))
		if err != nil {
			return
		}
		if int(pkt.Header.BodyLen) != len(pkt.Body) {
			t.Fatalf("BodyLen says %d but body is %d bytes", pkt.Header.BodyLen, len(pkt.Body))
		}

		var out bytes.Buffer
		if err := pkt.Encode(&out); err != nil {
			t.Fatalf("re-encoding an accepted packet failed: %v", err)
		}
		again, err := Decode(bytes.NewReader(out.Bytes()))
		if err != nil {
			t.Fatalf("re-decoding an accepted packet failed: %v", err)
		}
		if again.Header != pkt.Header || !bytes.Equal(again.Body, pkt.Body) {
			t.Fatal("round trip changed the packet")
		}
	})
}

// The account decoders run on the very first packet of a connection, before
// anything is authenticated.
func FuzzDecodeCredentials(f *testing.F) {
	body, _ := EncodeCredentials(&Credentials{Username: "alice", Password: "a long password", DeviceName: "mac"})
	f.Add(body)
	f.Add([]byte{})
	f.Add([]byte{0xFF, 0xFF, 0xFF})

	f.Fuzz(func(t *testing.T, data []byte) {
		c, err := DecodeCredentials(data)
		if err != nil {
			return
		}
		again, err := EncodeCredentials(&c)
		if err != nil {
			t.Fatalf("re-encoding accepted credentials failed: %v", err)
		}
		if !bytes.Equal(again, data) {
			t.Fatal("round trip changed the credentials")
		}
	})
}

func FuzzDecodeResume(f *testing.F) {
	f.Add(EncodeResume([SessionTokenSize]byte{1}, &PreKeyBundle{}))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		token, b, err := DecodeResume(data)
		if err != nil {
			return
		}
		if !bytes.Equal(EncodeResume(token, &b), data) {
			t.Fatal("round trip changed the resume body")
		}
	})
}

func FuzzDecodeError(f *testing.F) {
	f.Add(EncodeError(ErrBadCredentials, "no"))
	f.Add([]byte{})
	f.Add([]byte{1, 0xFF, 0xFF})

	f.Fuzz(func(t *testing.T, data []byte) {
		e, err := DecodeError(data)
		if err != nil || len(data) == 0 {
			return
		}
		if !bytes.Equal(EncodeError(e.Code, e.Message), data) {
			t.Fatal("round trip changed the error body")
		}
	})
}

func FuzzDecodeMyGroups(f *testing.F) {
	f.Add(EncodeMyGroups([]GroupRef{{ID: [IDSize]byte{1}, Name: "family"}}))
	f.Add([]byte{})
	f.Add([]byte{0xFF, 0xFF})

	f.Fuzz(func(t *testing.T, data []byte) {
		groups, err := DecodeMyGroups(data)
		if err != nil {
			return
		}
		if !bytes.Equal(EncodeMyGroups(groups), data) {
			t.Fatal("round trip changed the group list")
		}
	})
}
