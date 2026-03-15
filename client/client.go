package main

import (
	"bufio"
	common "common"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

const StandardChunkSize = 32 * 1024

var (
	rotationMu sync.Mutex
	mgr        *ClientManager
	idMgr      *IdentityManager
	sessionMgr *SessionManager
	conn       net.Conn
	reader     *bufio.Reader
	connLock   sync.Mutex
)

func main() {
	f, err := os.OpenFile("client.log", os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		fmt.Printf("Error opening client.log: %v\n", err)
	} else {
		log.SetOutput(f)
		defer f.Close()
	}

	reader = bufio.NewReader(os.Stdin)

	idMgr, err = NewIdentityManager()
	if err != nil {
		log.Fatalf("Failed to init identity: %v", err)
	}

	tuiPrint("Enter server address (default :8080): ")
	addr, _ := reader.ReadString('\n')
	addr = strings.TrimSpace(addr)
	if addr == "" {
		addr = ":8080"
	}

	tuiPrint("Enter your username: ")
	username, _ := reader.ReadString('\n')
	username = strings.TrimSpace(username)

	conn, err = net.Dial("tcp", addr)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	userID, err := performHandshake(username, idMgr.PublicKey)
	if err != nil {
		log.Fatal(err)
	}

	mgr = NewClientManager(userID, username)
	log.Printf("[DEBUG] main: mgr.UserID set to %x\n", mgr.UserID)
	sessionMgr = NewSessionManager(idMgr)

	go readLoop()

	p := tea.NewProgram(initialModel(), tea.WithAltScreen())
	program = p
	if _, err := p.Run(); err != nil {
		log.Fatalf("Error running program: %v", err)
	}
}

func performHandshake(username string, pubKey [32]byte) ([16]byte, error) {
	body := make([]byte, 0, 32+len(username))
	body = append(body, pubKey[:]...)
	body = append(body, []byte(username)...)

	pkt := common.Packet{
		Header: common.Header{
			MsgType: common.CtrlLogin,
			BodyLen: uint32(len(body)),
		},
		Body: body,
	}
	if err := sendPacket(&pkt); err != nil {
		return [16]byte{}, err
	}

	resp, err := common.Decode(conn)
	if err != nil {
		return [16]byte{}, err
	}

	if resp.Header.MsgType != common.CtrlLoginAck {
		return [16]byte{}, fmt.Errorf("unexpected handshake response: %d", resp.Header.MsgType)
	}

	var userID [16]byte
	copy(userID[:], resp.Body)
	tuiPrintf("Logged in! UserID: %x", userID)
	return userID, nil
}

func readLoop() {
	for {
		pkt, err := common.Decode(conn)
		if err != nil {
			if err != io.EOF {
				tuiPrintf("[ERROR] Disconnected: %v", err)
			}
			os.Exit(1)
		}

		if pkt.Header.Flags&common.FlagEncrypted != 0 {
			if mgr.IsGroup(pkt.Header.ConversationID) {
				if err := sessionMgr.DecryptGroupPacket(&pkt); err != nil {
					log.Printf("[ERROR] Group Decrypt failed: %v", err)
					continue
				}
				if sess, ok := sessionMgr.GetGroupSession(pkt.Header.ConversationID); ok {
					sess.IncrementCounter()
					if sess.ShouldRotate() && mgr.IsGroupAdmin(pkt.Header.ConversationID) {
						go rotateGroupKey(pkt.Header.ConversationID)
					}
				}
			} else {
				if err := sessionMgr.DecryptPacket(&pkt); err != nil {
					log.Printf("[ERROR] Failed to decrypt packet from %x: %v", pkt.Header.SenderID[:4], err)
					continue
				}
			}
		}

		switch pkt.Header.MsgType {
		case common.MsgControl:
			if pkt.Header.Flags&common.FlagHandshake != 0 {
				sender := mgr.GetUsername(pkt.Header.SenderID)
				if err := sessionMgr.HandleHandshake(pkt); err != nil {
					log.Printf("Handshake failed: %v", err)
				} else {
					tuiPrintf("[INFO] Secure Session established with %s", sender)
				}
			}

		case common.MsgText:
			name := mgr.GetConversationName(pkt.Header.ConversationID)
			sender := mgr.GetUsername(pkt.Header.SenderID)
			if program != nil {
				go program.Send(NetworkMsg{
					ConversationID: pkt.Header.ConversationID,
					SenderName:     sender,
					Content:        string(pkt.Body),
					IsSystemMeta:   false,
				})
			} else {
				fmt.Printf("[%s] %s: %s\n", name, sender, string(pkt.Body))
			}

		case common.MsgFileMeta:
			meta, err := common.DecodeFileMetadata(pkt.Body)
			if err != nil {
				log.Printf("Bad file meta: %v", err)
				continue
			}
			sender := mgr.GetUsername(pkt.Header.SenderID)
			tuiPrintf("[%s] Receiving file from %s: %s (%d bytes)",
				mgr.GetConversationName(pkt.Header.ConversationID),
				sender, meta.FileName, meta.FileSize)
			mgr.HandleFileMeta(pkt.Header.MessageID, meta)

		case common.MsgFileChunk:
			chunk, err := common.DecodeFileChunk(pkt.Body)
			if err != nil {
				log.Printf("Bad chunk: %v", err)
				continue
			}
			mgr.HandleFileChunk(pkt.Header.MessageID, chunk)

		case common.CtrlDirectAck:
			if len(pkt.Body) < 48 {
				continue
			}
			var convID [16]byte
			copy(convID[:], pkt.Body[:16])
			var peerKey [32]byte
			copy(peerKey[:], pkt.Body[16:48])

			mgr.RegisterConversation(convID, "Private Chat", false)

			if _, ok := sessionMgr.GetSession(convID); ok {
				tuiPrintf("[INFO] Session already exists for %x, skipping handshake.", convID[:4])
				continue
			}

			tuiPrintln("[INFO] Key Exchange Initiating...")

			handshakePkt, err := sessionMgr.PerformHandshake(convID, peerKey)
			if err == nil {
				sendPacket(handshakePkt)
			} else {
				tuiPrintf("[ERROR] Handshake init failed: %v", err)
			}

		case common.CtrlDirectInit:
			if len(pkt.Body) < 48 {
				continue
			}
			var convID [16]byte
			copy(convID[:], pkt.Body[:16])

			senderName := string(pkt.Body[48:])
			mgr.AddUser(pkt.Header.SenderID, senderName)
			mgr.RegisterConversation(pkt.Header.ConversationID, "Private Chat: "+senderName, false)

			tuiPrintf("[INFO] Private Chat requested by %s. Waiting for Handshake...", senderName)

		case common.CtrlGroupCreate:
			if len(pkt.Body) < 17 {
				continue
			}
			var convID [16]byte
			copy(convID[:], pkt.Body[0:16])
			nameLen := int(pkt.Body[16])
			if len(pkt.Body) < 17+nameLen+1 {
				continue
			}
			groupName := string(pkt.Body[17 : 17+nameLen])
			mgr.RegisterConversation(convID, groupName, true)
			offset := 17 + nameLen
			memberCount := int(pkt.Body[offset])
			offset++
			for i := 0; i < memberCount; i++ {
				if offset+17 > len(pkt.Body) {
					break
				}
				var mID [16]byte
				copy(mID[:], pkt.Body[offset:offset+16])
				offset += 16
				mNameLen := int(pkt.Body[offset])
				offset++
				if offset+mNameLen > len(pkt.Body) {
					break
				}
				mName := string(pkt.Body[offset : offset+mNameLen])
				offset += mNameLen
				mgr.AddUser(mID, mName)
				mgr.AddMemberToGroup(convID, mID)
			}

			mgr.SetGroupAdmin(convID, pkt.Header.SenderID, true)

			log.Printf("[DEBUG] CtrlGroupCreate: Packet SenderID=%x, My UserID=%x\n", pkt.Header.SenderID, mgr.UserID)
			if pkt.Header.SenderID == mgr.UserID {
				tuiPrintf("[INFO] You are Admin of group %s. Initializing Key...", groupName)
				log.Printf("[DEBUG] readLoop: Triggering initial rotation for %x\n", convID)
				go rotateGroupKey(convID)
			}

		case common.CtrlGroupAdd:
			if len(pkt.Body) < 17 {
				continue
			}
			var convID [16]byte
			copy(convID[:], pkt.Body[0:16])
			nameLen := int(pkt.Body[16])
			offset := 17
			var groupName string
			if len(pkt.Body) >= offset+nameLen {
				groupName = string(pkt.Body[offset : offset+nameLen])
				offset += nameLen
			} else {
				continue
			}
			if mgr.GetConversationName(convID) == fmt.Sprintf("%x", convID[:4]) {
				mgr.RegisterConversation(convID, groupName, true)
			}
			if len(pkt.Body) < offset+17 {
				continue
			}
			var userID [16]byte
			copy(userID[:], pkt.Body[offset:offset+16])
			offset += 16
			uNameLen := int(pkt.Body[offset])
			offset++
			if len(pkt.Body) < offset+uNameLen {
				continue
			}
			userName := string(pkt.Body[offset : offset+uNameLen])
			mgr.AddUser(userID, userName)
			mgr.AddMemberToGroup(convID, userID)
			tuiPrintf("[INFO] User %s added to group %s", userName, groupName)

			if mgr.IsGroupAdmin(convID) && pkt.Header.SenderID == mgr.UserID {
				go rotateGroupKey(convID)
			}

		case common.CtrlGroupRemove:
			if len(pkt.Body) < 32 {
				continue
			}
			var convID [16]byte
			copy(convID[:], pkt.Body[0:16])
			var userID [16]byte
			copy(userID[:], pkt.Body[16:32])

			uName := mgr.GetUsername(userID)
			groupName := mgr.GetConversationName(convID)
			mgr.RemoveMemberFromGroup(convID, userID)
			tuiPrintf("[INFO] User %s removed from group %s", uName, groupName)

			if mgr.IsGroupAdmin(convID) && pkt.Header.SenderID == mgr.UserID {
				go rotateGroupKey(convID)
			}

		case common.CtrlGroupMakeAdmin:
			if len(pkt.Body) < 32 {
				continue
			}
			var convID [16]byte
			copy(convID[:], pkt.Body[0:16])
			var userID [16]byte
			copy(userID[:], pkt.Body[16:32])

			uName := mgr.GetUsername(userID)
			groupName := mgr.GetConversationName(convID)
			mgr.SetGroupAdmin(convID, userID, true)
			tuiPrintf("[INFO] User %s is now an Admin of group %s", uName, groupName)

		case common.CtrlGroupRemoveAdmin:
			if len(pkt.Body) < 32 {
				continue
			}
			var convID [16]byte
			copy(convID[:], pkt.Body[0:16])
			var userID [16]byte
			copy(userID[:], pkt.Body[16:32])

			uName := mgr.GetUsername(userID)
			groupName := mgr.GetConversationName(convID)
			mgr.SetGroupAdmin(convID, userID, false)
			tuiPrintf("[INFO] User %s is no longer an Admin of group %s", uName, groupName)

		case common.CtrlPubAck:
			if len(pkt.Body) < 48 {
				continue
			}
			var userID [16]byte
			copy(userID[:], pkt.Body[:16])
			var pubKey [32]byte
			copy(pubKey[:], pkt.Body[16:48])
			mgr.UpdatePublicKey(userID, pubKey)

		case common.CtrlGroupKeyUpdate:

			if len(pkt.Body) < 16+4+32 {
				continue
			}
			var groupID [16]byte
			copy(groupID[:], pkt.Body[:16])
			version := binary.BigEndian.Uint32(pkt.Body[16:20])
			var key [32]byte
			copy(key[:], pkt.Body[20:52])

			if !mgr.IsUserAdmin(groupID, pkt.Header.SenderID) {
				log.Printf("[WARNING] Unauthorized Key Update dropped from %x for group %x", pkt.Header.SenderID[:4], groupID[:4])
				continue
			}

			sessionMgr.CreateGroupSession(groupID, key, version, false)
			tuiPrintf("[INFO] Group Key Updated for %s (v%d)", mgr.GetConversationName(groupID), version)

			ackBody := make([]byte, 20)
			copy(ackBody[:16], groupID[:])
			binary.BigEndian.PutUint32(ackBody[16:], version)

			ackPkt := common.Packet{
				Header: common.Header{
					MsgType:        common.CtrlGroupKeyUpdateAck,
					ConversationID: pkt.Header.ConversationID,
					SenderID:       mgr.UserID,
					BodyLen:        20,
				},
				Body: ackBody,
			}
			if err := sessionMgr.EncryptPacket(&ackPkt); err == nil {
				sendPacket(&ackPkt)
			}
		}
	}
}

func createGroup(name string, users []string) {
	if name == "" {
		tuiPrintln("Group Name cannot be empty")
		return
	}
	body := make([]byte, 0)
	body = append(body, byte(len(name)))
	body = append(body, []byte(name)...)
	body = append(body, byte(len(users)))

	for _, u := range users {
		u = strings.TrimSpace(u)
		body = append(body, byte(len(u)))
		body = append(body, []byte(u)...)
	}

	pkt := common.Packet{
		Header: common.Header{
			MsgType: common.CtrlGroupCreate,
			BodyLen: uint32(len(body)),
		},
		Body: body,
	}
	sendPacket(&pkt)
}

func startPrivateChat(name string) {
	if name == "" {
		tuiPrintln("Target username cannot be empty")
		return
	}
	pkt := common.Packet{
		Header: common.Header{
			MsgType: common.CtrlDirectInit,
			BodyLen: uint32(len(name)),
		},
		Body: []byte(name),
	}
	sendPacket(&pkt)
}

func listConversations() {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()
	i := 0
	for id, info := range mgr.Conversations {
		typeStr := "Private"
		if info.IsGroup {
			typeStr = "Group"
		}
		tuiPrintf("%d. %s [%s] (%x)", i, info.Name, typeStr, id[:4])
		i++
	}
}

func addMember(convID [16]byte, username string) {
	if !mgr.IsGroup(convID) {
		tuiPrintln("Error: This is not a group.")
		return
	}
	if !mgr.IsGroupAdmin(convID) {
		tuiPrintln("Error: Only admins can perform this action.")
		return
	}
	if username == "" {
		return
	}

	body := make([]byte, 0)
	body = append(body, convID[:]...)
	body = append(body, byte(len(username)))
	body = append(body, []byte(username)...)

	pkt := common.Packet{
		Header: common.Header{
			MsgType: common.CtrlGroupAdd,
			BodyLen: uint32(len(body)),
		},
		Body: body,
	}
	sendPacket(&pkt)
	tuiPrintln("Add member request sent.")
}

func removeMember(convID [16]byte, username string) {
	if !mgr.IsGroup(convID) {
		tuiPrintln("Error: This is not a group.")
		return
	}
	if !mgr.IsGroupAdmin(convID) {
		tuiPrintln("Error: Only admins can perform this action.")
		return
	}
	if username == "" {
		return
	}

	body := make([]byte, 0)
	body = append(body, convID[:]...)
	body = append(body, byte(len(username)))
	body = append(body, []byte(username)...)

	pkt := common.Packet{
		Header: common.Header{
			MsgType: common.CtrlGroupRemove,
			BodyLen: uint32(len(body)),
		},
		Body: body,
	}
	sendPacket(&pkt)
	tuiPrintln("Remove member request sent.")
}

func makeGroupAdmin(convID [16]byte, username string) {
	if !mgr.IsGroup(convID) {
		tuiPrintln("Error: This is not a group.")
		return
	}
	if !mgr.IsGroupAdmin(convID) {
		tuiPrintln("Error: Only admins can perform this action.")
		return
	}
	if username == "" {
		return
	}

	body := make([]byte, 0)
	body = append(body, convID[:]...)
	body = append(body, byte(len(username)))
	body = append(body, []byte(username)...)

	pkt := common.Packet{
		Header: common.Header{
			MsgType: common.CtrlGroupMakeAdmin,
			BodyLen: uint32(len(body)),
		},
		Body: body,
	}
	sendPacket(&pkt)
	tuiPrintln("Make admin request sent.")
}

func removeGroupAdmin(convID [16]byte, username string) {
	if !mgr.IsGroup(convID) {
		tuiPrintln("Error: This is not a group.")
		return
	}
	if !mgr.IsGroupAdmin(convID) {
		tuiPrintln("Error: Only admins can perform this action.")
		return
	}
	if username == "" {
		return
	}

	body := make([]byte, 0)
	body = append(body, convID[:]...)
	body = append(body, byte(len(username)))
	body = append(body, []byte(username)...)

	pkt := common.Packet{
		Header: common.Header{
			MsgType: common.CtrlGroupRemoveAdmin,
			BodyLen: uint32(len(body)),
		},
		Body: body,
	}
	sendPacket(&pkt)
	tuiPrintln("Remove admin request sent.")
}

func leaveGroup(convID [16]byte) {
	if !mgr.IsGroup(convID) {
		tuiPrintln("Error: This is not a group.")
		return
	}

	username := mgr.Username
	body := make([]byte, 0)
	body = append(body, convID[:]...)
	body = append(body, byte(len(username)))
	body = append(body, []byte(username)...)

	pkt := common.Packet{
		Header: common.Header{
			MsgType: common.CtrlGroupRemove,
			BodyLen: uint32(len(body)),
		},
		Body: body,
	}
	sendPacket(&pkt)
	tuiPrintln("Leave group request sent.")
}

func sendFile(convID [16]byte, path string) {
	if path == "" {
		return
	}
	f, err := os.Open(path)
	if err != nil {
		tuiPrintln("Error opening file:", err)
		return
	}
	defer f.Close()

	info, _ := f.Stat()
	size := info.Size()
	totalChunks := int32((size + StandardChunkSize - 1) / StandardChunkSize)
	msgID := genID()

	meta := common.FileMetadata{
		FileName:    filepath.Base(path),
		FileType:    "application/octet-stream",
		FileSize:    size,
		TotalChunks: totalChunks,
	}
	metaBytes := meta.Encode()

	metaPkt := common.Packet{
		Header: common.Header{
			MsgType:        common.MsgFileMeta,
			ConversationID: convID,
			MessageID:      msgID,
			SenderID:       mgr.UserID,
			BodyLen:        uint32(len(metaBytes)),
		},
		Body: metaBytes,
	}

	if mgr.IsGroup(convID) {
		rotationMu.Lock()
		err := sessionMgr.EncryptGroupPacket(&metaPkt)
		rotationMu.Unlock()

		if err != nil {
			tuiPrintf("[ERROR] Group Encryption failed for meta: %v", err)
			return
		}
		if sess, ok := sessionMgr.GetGroupSession(convID); ok {
			sess.IncrementCounter()
			if sess.ShouldRotate() && mgr.IsGroupAdmin(convID) {
				go rotateGroupKey(convID)
			}
		}
	} else {
		if err := sessionMgr.EncryptPacket(&metaPkt); err != nil {
			tuiPrintf("[ERROR] Encryption failed for meta: %v", err)
			return
		}
	}
	sendPacket(&metaPkt)

	buf := make([]byte, StandardChunkSize)
	chunkNo := int32(0)
	for {
		n, err := f.Read(buf)
		if err != nil && err != io.EOF {
			break
		}
		if n == 0 {
			break
		}
		chunkData := make([]byte, n)
		copy(chunkData, buf[:n])
		c := common.FileChunk{
			ChunkNo:   chunkNo,
			ChunkData: chunkData,
		}
		cBytes := c.Encode()
		chkPkt := common.Packet{
			Header: common.Header{
				MsgType:        common.MsgFileChunk,
				ConversationID: convID,
				MessageID:      msgID,
				SenderID:       mgr.UserID,
				BodyLen:        uint32(len(cBytes)),
			},
			Body: cBytes,
		}
		if mgr.IsGroup(convID) {
			rotationMu.Lock()
			err := sessionMgr.EncryptGroupPacket(&chkPkt)
			rotationMu.Unlock()

			if err != nil {
				tuiPrintf("[ERROR] Group Encryption failed for chunk: %v", err)
				continue
			}
		} else {
			if err := sessionMgr.EncryptPacket(&chkPkt); err != nil {
				tuiPrintf("[ERROR] Encryption failed for chunk: %v", err)
				continue
			}
		}
		sendPacket(&chkPkt)
		chunkNo++
	}
	tuiPrintln("File sent!")
}

func genID() [16]byte {
	var id [16]byte
	rand.Read(id[:])
	return id
}

func sendPacket(pkt *common.Packet) error {
	connLock.Lock()
	defer connLock.Unlock()
	return pkt.Encode(conn)
}



func rotateGroupKey(groupID [16]byte) {
	rotationMu.Lock()
	defer rotationMu.Unlock()

	log.Printf("[DEBUG] rotateGroupKey: Starting rotation for %x\n", groupID)

	if !mgr.IsGroupAdmin(groupID) {
		log.Printf("[DEBUG] rotateGroupKey: Not admin for %x, aborting\n", groupID)
		return
	}

	var newKey [32]byte
	if _, err := rand.Read(newKey[:]); err != nil {
		log.Printf("Failed to gen key: %v", err)
		return
	}

	var newVersion uint32 = 1
	if sess, ok := sessionMgr.GetGroupSession(groupID); ok {
		newVersion = sess.CurrentVersion + 1
	}

	members := mgr.GetGroupMembers(groupID)
	log.Printf("[DEBUG] rotateGroupKey: Found %d members for group %x\n", len(members), groupID)

	for _, memberID := range members {
		if memberID == mgr.UserID {
			continue
		}
		tuiPrintf("[DEBUG] rotateGroupKey: Processing member %x\n", memberID)

		convID := common.HashIDs(mgr.UserID, memberID)
		if _, ok := sessionMgr.GetSession(convID); !ok {
			memberUName := mgr.GetUsername(memberID)
			initPkt := common.Packet{
				Header: common.Header{
					MsgType: common.CtrlDirectInit,
					BodyLen: uint32(len(memberUName)),
				},
				Body: []byte(memberUName),
			}
			sendPacket(&initPkt)
			log.Printf("[DEBUG] rotateGroupKey: Sent CtrlDirectInit for %s\n", memberUName)

			established := false
			for i := 0; i < 50; i++ {
				if _, ok := sessionMgr.GetSession(convID); ok {
					established = true
					break
				}
				time.Sleep(100 * time.Millisecond)
			}

			if !established {
				log.Printf("Handshake timeout with %x (no session after 5s)", memberID[:4])
				continue
			}
		}

		payload := make([]byte, 16+4+32)
		copy(payload[0:16], groupID[:])
		binary.BigEndian.PutUint32(payload[16:20], newVersion)
		copy(payload[20:52], newKey[:])

		pkt := common.Packet{
			Header: common.Header{
				MsgType:        common.CtrlGroupKeyUpdate,
				ConversationID: convID,
				SenderID:       mgr.UserID,
				BodyLen:        uint32(len(payload)),
			},
			Body: payload,
		}

		if err := sessionMgr.EncryptPacket(&pkt); err != nil {
			log.Printf("Failed to encrypt key update for %x: %v", memberID[:4], err)
			continue
		}

		sendPacket(&pkt)
		log.Printf("[DEBUG] rotateGroupKey: Sent Key Update to %x\n", memberID)
	}

	time.Sleep(500 * time.Millisecond)

	sessionMgr.CreateGroupSession(groupID, newKey, newVersion, true)
	tuiPrintf("[INFO] Rotated Group Key to v%d", newVersion)
	log.Printf("[DEBUG] rotateGroupKey: Created session for GroupID %x\n", groupID)
}
