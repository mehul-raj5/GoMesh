package main

import (
	"bufio"
	common "common"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

var (
	mgr        *ClientManager
	idMgr      *IdentityManager
	stateStore *StateStore
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
	stateStore, err = OpenStateStore(StateDirName, idMgr.PublicKey)
	if err != nil {
		log.Fatalf("Failed to open state store: %v", err)
	}
	if err := idMgr.LoadPreKeys(stateStore); err != nil {
		log.Fatalf("Failed to load prekeys: %v", err)
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

	userID, err := performHandshake(username)
	if err != nil {
		log.Fatal(err)
	}

	mgr = NewClientManager(userID, username)
	log.Printf("[DEBUG] main: mgr.UserID set to %x\n", mgr.UserID)
	sessionMgr = NewSessionManager(idMgr, userID)
	sessionMgr.KnownKey = mgr.GetPublicKey
	sessionMgr.OnReplaced = discardHeld
	restoreSessions()

	go readLoop()

	p := tea.NewProgram(initialModel(), tea.WithAltScreen())
	program = p
	if _, err := p.Run(); err != nil {
		log.Fatalf("Error running program: %v", err)
	}
}

// performHandshake logs in: it presents the prekey bundle, answers the server's
// challenge with a signature from the identity signing key, and returns the user
// ID the server assigns.
func performHandshake(username string) ([16]byte, error) {
	bundle := idMgr.Bundle()
	body := common.EncodeLogin(&bundle, username)

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

	challenge, err := common.Decode(conn)
	if err != nil {
		return [16]byte{}, err
	}
	if challenge.Header.MsgType == common.CtrlError {
		return [16]byte{}, errors.New("login rejected by the server")
	}
	if challenge.Header.MsgType != common.CtrlLoginChallenge || len(challenge.Body) != common.LoginNonceSize {
		return [16]byte{}, fmt.Errorf("unexpected login challenge: type %d", challenge.Header.MsgType)
	}
	var nonce [common.LoginNonceSize]byte
	copy(nonce[:], challenge.Body)

	sig := idMgr.SignLogin(nonce, username)
	proof := common.Packet{
		Header: common.Header{
			MsgType: common.CtrlLoginProof,
			BodyLen: common.SignatureSize,
		},
		Body: sig[:],
	}
	if err := sendPacket(&proof); err != nil {
		return [16]byte{}, err
	}

	resp, err := common.Decode(conn)
	if err != nil {
		return [16]byte{}, err
	}
	if resp.Header.MsgType == common.CtrlError {
		return [16]byte{}, errors.New("login rejected by the server")
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
		deliver(pkt)
	}
}

// deliver decrypts a packet if it needs it and hands it to dispatch. A packet
// whose key has not arrived yet is held rather than dropped, and comes back
// through here once the missing key lands.
func deliver(pkt common.Packet) {
	wasEncrypted := pkt.Header.Flags&common.FlagEncrypted != 0
	convID := pkt.Header.ConversationID

	if err := tryDecrypt(&pkt); err != nil {
		if !Recoverable(err) {
			log.Printf("[ERROR] Dropping packet from %x: %v", pkt.Header.SenderID[:4], err)
			return
		}

		pending.Park(convID, pkt)

		// A missing sender key is already on its way over the direct channel we
		// share with that member, and a missing epoch is waiting on a packet
		// that is itself in flight, so there is nothing to ask for. Not knowing
		// the conversation at all is different: the roster has to be fetched.
		if errors.Is(err, ErrNoSession) || errors.Is(err, ErrNoGroupSession) {
			requestConvInfo(convID)
		}
		return
	}

	direct := wasEncrypted && !mgr.IsGroup(convID)
	if direct {
		learnDirectPeer(convID)
	}
	dispatch(pkt)

	// Reading this message may have supplied what held ones were waiting for: the
	// missing epoch of a direct chain, in particular, arrives as an ordinary packet.
	if direct {
		replay(pending.Release(convID))
	}
}

// discardHeld drops packets parked for a conversation whose session was just
// replaced. They belong to a session that no longer exists, so replaying them
// could only park them again.
func discardHeld(convID [16]byte) {
	pending.Release(convID)
}

// learnDirectPeer registers a conversation first heard of through an incoming
// message, which is how the responder side of a chat comes to exist: its session
// was built from the message itself. The roster supplies the peer's name, checks
// the identity key it claimed, and replaces this placeholder.
func learnDirectPeer(convID [16]byte) {
	if mgr.HasConversation(convID) {
		return
	}
	mgr.RegisterConversation(convID, fmt.Sprintf("Private Chat: %x", convID[:4]), false)
	requestConvInfo(convID)
}

// tryDecrypt unwraps an encrypted packet using whichever session applies.
//
// An unknown conversation reads as a direct one, because IsGroup returns false
// for anything unregistered. That resolves itself: the roster reply says which
// it really is, and the replayed packet then takes the right branch.
func tryDecrypt(pkt *common.Packet) error {
	if pkt.Header.Flags&common.FlagEncrypted == 0 {
		return nil
	}
	if mgr.IsGroup(pkt.Header.ConversationID) {
		return sessionMgr.DecryptGroupPacket(pkt)
	}
	return sessionMgr.DecryptPacket(pkt)
}

func dispatch(pkt common.Packet) {
	{
		switch pkt.Header.MsgType {
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

		case common.MsgMediaMeta:
			meta, err := common.DecodeMediaMetadata(pkt.Body)
			if err != nil {
				log.Printf("Bad media meta: %v", err)
				return
			}
			sender := mgr.GetUsername(pkt.Header.SenderID)
			tuiPrintf("[%s] Incoming media from %s: %s (%d bytes)",
				mgr.GetConversationName(pkt.Header.ConversationID),
				sender, meta.FileName, meta.FileSize)
			handleIncomingMedia(pkt.Header.ConversationID, sender, meta)

		case common.CtrlUploadAck:
			strs, err := common.DecodeSignedURLPayload(pkt.Body, 2)
			if err != nil {
				strs = nil
			}
			mgr.DeliverURL(pkt.Header.MessageID, strs)

		case common.CtrlDownloadAck:
			strs, err := common.DecodeSignedURLPayload(pkt.Body, 1)
			if err != nil {
				strs = nil
			}
			mgr.DeliverURL(pkt.Header.MessageID, strs)

		case common.CtrlDirectAck:
			// convID(16) || peerID(16) || prekey bundle || peerName
			if len(pkt.Body) < 32+common.PreKeyBundleSize {
				return
			}
			var convID, peerID [16]byte
			copy(convID[:], pkt.Body[:16])
			copy(peerID[:], pkt.Body[16:32])
			bundle, err := common.DecodePreKeyBundle(pkt.Body[32:])
			if err != nil {
				return
			}
			peerName := string(pkt.Body[32+common.PreKeyBundleSize:])

			mgr.AddUser(peerID, peerName)
			mgr.UpdatePublicKey(peerID, bundle.IdentityKey)
			mgr.RegisterConversation(convID, "Private Chat: "+peerName, false)

			// No packet is sent back. The peer builds its side from the handshake
			// fields in our first message, so it need not be online.
			//
			// An ack is only ever the answer to a /dm, and /dm on a chat that
			// exists means start over. Only an ack we asked for does that, though:
			// an unsolicited one must not be able to reset a working session.
			res, err := sessionMgr.OpenDirectSession(convID, peerID, peerName, bundle, takeDMRequest(peerName))
			if err != nil {
				tuiPrintf("[ERROR] Could not open chat with %s: %v", peerName, err)
				return
			}
			if res.Replaced {
				discardHeld(convID)
			}
			if res.IdentityChanged {
				tuiPrintf("[WARN] %s's identity key has changed since this chat began. Compare safety numbers before trusting it.", peerName)
			}
			if res.Replaced {
				tuiPrintf("[INFO] Started a fresh secure session with %s. Messages either of you sent on the old one may not arrive.", peerName)
			} else {
				tuiPrintf("[INFO] Secure session ready with %s", peerName)
			}

		case common.CtrlSenderKey:
			sk, err := common.DecodeSenderKey(pkt.Body)
			if err != nil {
				log.Printf("[ERROR] Bad sender key from %x: %v", pkt.Header.SenderID[:4], err)
				return
			}

			// Membership is not checked here. The server refuses to relay group
			// traffic from a non-member, so a chain installed for one is inert,
			// and a key can legitimately arrive before the roster that would
			// confirm it.
			if err := sessionMgr.SetPeerSenderKey(sk.GroupID, pkt.Header.SenderID, sk.ChainKey, sk.Epoch); err != nil {
				log.Printf("[INFO] Ignoring sender key: %v", err)
				return
			}
			replay(pending.ReleaseSender(sk.GroupID, pkt.Header.SenderID))

		case common.CtrlGroupCreate:
			if len(pkt.Body) < 17 {
				return
			}
			var convID [16]byte
			copy(convID[:], pkt.Body[0:16])
			nameLen := int(pkt.Body[16])
			if len(pkt.Body) < 17+nameLen {
				return
			}
			groupName := string(pkt.Body[17 : 17+nameLen])

			members, _, err := parseRoster(pkt.Body, 17+nameLen)
			if err != nil {
				log.Printf("[ERROR] Bad group roster for %x: %v", convID[:4], err)
				return
			}

			mgr.RegisterConversation(convID, groupName, true)
			for _, m := range members {
				mgr.AddUser(m.UserID, m.Name)
				mgr.UpdatePublicKey(m.UserID, m.PubKey)
				mgr.AddMemberToGroup(convID, m.UserID)
			}
			mgr.SetGroupAdmin(convID, pkt.Header.SenderID, true)

			tuiPrintf("[INFO] Group %s created with %d members. Distributing key...", groupName, len(members))
			bootstrapGroupKeys(convID, members)

		case common.CtrlGroupAdd:
			// convID(16) || nameLen(1) || name || userID(16) || pubKey(32) || nameLen(1) || name
			if len(pkt.Body) < 17 {
				return
			}
			var convID [16]byte
			copy(convID[:], pkt.Body[0:16])
			nameLen := int(pkt.Body[16])
			offset := 17
			if len(pkt.Body) < offset+nameLen {
				return
			}
			groupName := string(pkt.Body[offset : offset+nameLen])
			offset += nameLen

			if len(pkt.Body) < offset+16+32+1 {
				return
			}
			var userID [16]byte
			copy(userID[:], pkt.Body[offset:offset+16])
			offset += 16
			var pubKey [32]byte
			copy(pubKey[:], pkt.Body[offset:offset+32])
			offset += 32
			uNameLen := int(pkt.Body[offset])
			offset++
			if len(pkt.Body) < offset+uNameLen {
				return
			}
			userName := string(pkt.Body[offset : offset+uNameLen])

			if mgr.GetConversationName(convID) == fmt.Sprintf("%x", convID[:4]) {
				mgr.RegisterConversation(convID, groupName, true)
			}
			mgr.AddUser(userID, userName)
			mgr.UpdatePublicKey(userID, pubKey)
			mgr.AddMemberToGroup(convID, userID)
			tuiPrintf("[INFO] User %s added to group %s", userName, groupName)

			// The joiner needs a direct channel with us before any key can reach
			// them, and the membership change means everyone rekeys.
			ensureDirectSession(userID, pubKey)
			distributeSenderKey(convID, mgr.GetGroupMembers(convID))

		case common.CtrlGroupRemove:
			if len(pkt.Body) < 32 {
				return
			}
			var convID [16]byte
			copy(convID[:], pkt.Body[0:16])
			var userID [16]byte
			copy(userID[:], pkt.Body[16:32])

			uName := mgr.GetUsername(userID)
			groupName := mgr.GetConversationName(convID)

			if userID == mgr.UserID {
				// We left, or were removed: forget the group and its keys.
				mgr.RemoveConversation(convID)
				sessionMgr.DeleteGroupSession(convID)
				tuiPrintf("[INFO] You are no longer a member of %s", groupName)
				return
			}

			mgr.RemoveMemberFromGroup(convID, userID)
			tuiPrintf("[INFO] User %s removed from group %s", uName, groupName)

			// Their chains are worthless to us now, and ours must become
			// worthless to them: a chain ratchets forward on its own, so without
			// a fresh key they would keep reading the group indefinitely.
			sessionMgr.ForgetSender(convID, userID)
			distributeSenderKey(convID, mgr.GetGroupMembers(convID))

		case common.CtrlGroupMakeAdmin:
			if len(pkt.Body) < 32 {
				return
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
				return
			}
			var convID [16]byte
			copy(convID[:], pkt.Body[0:16])
			var userID [16]byte
			copy(userID[:], pkt.Body[16:32])

			uName := mgr.GetUsername(userID)
			groupName := mgr.GetConversationName(convID)
			mgr.SetGroupAdmin(convID, userID, false)
			tuiPrintf("[INFO] User %s is no longer an Admin of group %s", uName, groupName)

		case common.CtrlConvInfoAck:
			info, err := common.DecodeConvInfo(pkt.Body)
			if err != nil {
				log.Printf("[ERROR] Bad conversation info: %v", err)
				return
			}
			applyConvInfo(info)

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

// dmRequests are the usernames the user has typed /dm for and not yet had
// answered. The server's ack names the peer, so this is how an ack is recognised
// as the answer to a request and not something unsolicited.
var (
	dmMu       sync.Mutex
	dmRequests = map[string]struct{}{}
)

func noteDMRequest(name string) {
	dmMu.Lock()
	dmRequests[name] = struct{}{}
	dmMu.Unlock()
}

// takeDMRequest reports whether the user asked for a chat with name, and
// consumes the request.
func takeDMRequest(name string) bool {
	dmMu.Lock()
	defer dmMu.Unlock()
	_, ok := dmRequests[name]
	delete(dmRequests, name)
	return ok
}

// startPrivateChat asks the server for a private chat with name. If one already
// exists, the answer starts a fresh secure session in its place, which is the
// way out of a conversation that has stopped decrypting.
func startPrivateChat(name string) {
	if name == "" {
		tuiPrintln("Target username cannot be empty")
		return
	}
	noteDMRequest(name)
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

// convInfoRetry throttles roster lookups. The server answers nothing at all
// when the asker is not a member, so without a cooldown a stream of packets for
// a conversation we have no business in would produce a request each.
const convInfoRetry = 5 * time.Second

var (
	convInfoMu    sync.Mutex
	convInfoAsked = map[[16]byte]time.Time{}
)

// requestConvInfo asks the server who is in a conversation, at most once per
// convInfoRetry per conversation.
func requestConvInfo(convID [16]byte) {
	convInfoMu.Lock()
	if last, asked := convInfoAsked[convID]; asked && time.Since(last) < convInfoRetry {
		convInfoMu.Unlock()
		return
	}
	convInfoAsked[convID] = time.Now()
	convInfoMu.Unlock()

	pkt := common.Packet{
		Header: common.Header{
			MsgType:        common.CtrlConvInfoRq,
			ConversationID: convID,
			SenderID:       mgr.UserID,
			BodyLen:        common.IDSize,
		},
		Body: convID[:],
	}
	if err := sendPacket(&pkt); err != nil {
		log.Printf("[ERROR] Could not request roster for %x: %v", convID[:4], err)
	}
}

// applyConvInfo takes the server's answer about a conversation we did not know,
// establishes whatever keys it makes possible, and replays what was held.
func applyConvInfo(info common.ConvInfo) {
	for _, m := range info.Members {
		if m.UserID == mgr.UserID {
			continue
		}
		mgr.AddUser(m.UserID, m.Name)
		mgr.UpdatePublicKey(m.UserID, m.PubKey)
	}

	if info.IsGroup {
		name := info.Name
		if name == "" {
			name = fmt.Sprintf("%x", info.ConvID[:4])
		}
		mgr.RegisterConversation(info.ConvID, name, true)
		sessionMgr.EnsureGroupSession(info.ConvID)

		for _, m := range info.Members {
			mgr.AddMemberToGroup(info.ConvID, m.UserID)
			if m.UserID == mgr.UserID {
				continue
			}
			// Sender keys travel over the direct channel with each member, so
			// those sessions have to exist before any of them can be read.
			ensureDirectSession(m.UserID, m.PubKey)
		}
		tuiPrintf("[INFO] Joined group %s (%d members)", name, len(info.Members))
	} else {
		for _, m := range info.Members {
			if m.UserID == mgr.UserID {
				continue
			}
			mgr.RegisterConversation(info.ConvID, "Private Chat: "+m.Name, false)

			// The session already exists if a message built it; what the roster
			// adds is the peer's name and signing key, and an independent check of
			// the identity key that message claimed.
			if err := sessionMgr.NotePeerKeys(info.ConvID, m.UserID, m.Name, m.PubKey, m.SigningKey); err != nil {
				if errors.Is(err, ErrPeerKeyMismatch) {
					tuiPrintf("[ERROR] %s presented an identity key the server does not recognise. The chat was closed.", m.Name)
				} else {
					log.Printf("[ERROR] Could not record keys for %s: %v", m.Name, err)
				}
				return
			}
			if _, ok := sessionMgr.GetSession(info.ConvID); ok {
				tuiPrintf("[INFO] Secure session ready with %s", m.Name)
				continue
			}

			// There is no session and the roster cannot make one: opening a chat
			// takes the peer's prekey bundle, which only a CtrlDirectAck carries.
			// This happens when this device lost its state, or closed the session
			// over a key mismatch, while the peer still holds an established one.
			// Whatever is held is unreadable, and replaying it would only park it
			// again, so it is discarded and the user is told how to recover. A new
			// chat from this side reaches the peer as a restart.
			dropped := len(pending.Release(info.ConvID))
			tuiPrintf("[WARN] %s is sending messages this device cannot read (%d held message(s) discarded). Run /dm %s to start a new secure session.",
				m.Name, dropped, m.Name)
			return
		}
	}

	replay(pending.Release(info.ConvID))
}

// ensureDirectSession is the group code's request for a direct channel with a
// member, over which sender keys travel. A ratcheted direct session needs the
// member's prekey bundle to open and the group roster does not carry one, so
// there is nothing to derive here yet; group messaging stays disabled until the
// roster does.
func ensureDirectSession(peerID [16]byte, pubKey [32]byte) {
	convID := common.HashIDs(mgr.UserID, peerID)
	if _, ok := sessionMgr.GetSession(convID); ok {
		return
	}
	log.Printf("[WARN] no direct session with %x; group keys cannot be distributed to them", peerID[:4])
}

// restoreSessions brings back the direct conversations saved by earlier runs, so
// a restart picks up each ratchet where it stopped instead of starting over.
func restoreSessions() {
	peers, err := sessionMgr.LoadSessions()
	if err != nil {
		log.Printf("[ERROR] Could not restore saved sessions: %v", err)
	}
	for _, p := range peers {
		name := p.Name
		if name == "" {
			name = fmt.Sprintf("%x", p.ConversationID[:4])
		}
		mgr.AddUser(p.PeerID, name)
		mgr.RegisterConversation(p.ConversationID, "Private Chat: "+name, false)

		// A key learned only from a message header is not the directory's word, and
		// must not come back out of KnownKey as if it were. The roster is asked for
		// again; its answer confirms the key, supplies the name, and clears the flag.
		if p.Unverified {
			requestConvInfo(p.ConversationID)
			continue
		}
		mgr.UpdatePublicKey(p.PeerID, p.IdentityKey)
	}
}

// replay feeds held packets back through delivery now that a key has arrived.
// Anything still blocked simply parks again.
func replay(pkts []common.Packet) {
	for _, p := range pkts {
		deliver(p)
	}
}

// parseRoster reads the member list the server appends to group broadcasts:
// count(1) then, per member, id(16) ‖ identityKey(32) ‖ nameLen(1) ‖ name.
func parseRoster(body []byte, offset int) ([]common.ConvMember, int, error) {
	if len(body) < offset+1 {
		return nil, offset, fmt.Errorf("roster truncated before member count")
	}
	count := int(body[offset])
	offset++

	members := make([]common.ConvMember, 0, count)
	for i := 0; i < count; i++ {
		if len(body) < offset+16+32+1 {
			return nil, offset, fmt.Errorf("roster truncated at member %d", i)
		}
		var m common.ConvMember
		copy(m.UserID[:], body[offset:offset+16])
		offset += 16
		copy(m.PubKey[:], body[offset:offset+32])
		offset += 32

		nameLen := int(body[offset])
		offset++
		if len(body) < offset+nameLen {
			return nil, offset, fmt.Errorf("roster truncated in member %d name", i)
		}
		m.Name = string(body[offset : offset+nameLen])
		offset += nameLen

		members = append(members, m)
	}
	return members, offset, nil
}

// bootstrapGroupKeys sets up everything this client needs to take part in a
// group: a direct session with every other member, its own sending chain, and
// that chain delivered to each of them.
//
// No round trip is needed for the sessions. The identity keys arrived with the
// roster, and the server registered the pairwise conversations when it created
// the group, so the key packets have somewhere to go immediately.
func bootstrapGroupKeys(groupID [16]byte, members []common.ConvMember) {
	sessionMgr.EnsureGroupSession(groupID)

	ids := make([][16]byte, 0, len(members))
	for _, m := range members {
		if m.UserID == mgr.UserID {
			continue
		}
		ensureDirectSession(m.UserID, m.PubKey)
		ids = append(ids, m.UserID)
	}
	distributeSenderKey(groupID, ids)
}

// distributeSenderKey generates a fresh sending chain for a group and unicasts
// it to every current member over the direct channel shared with each. Called
// when the group is first keyed and again on every membership change.
func distributeSenderKey(groupID [16]byte, memberIDs [][16]byte) {
	// Only the key RotateSenderKey returns may be sent. The live chain ratchets
	// forward with every message, so reading it back later would hand peers a
	// key that cannot open anything already sent in this epoch.
	key, epoch, err := sessionMgr.RotateSenderKey(groupID)
	if err != nil {
		tuiPrintf("[ERROR] Could not generate a sender key: %v", err)
		return
	}
	payload := (&common.SenderKeyPayload{GroupID: groupID, Epoch: epoch, ChainKey: key}).Encode()

	sent, failed := 0, 0
	for _, id := range memberIDs {
		if id == mgr.UserID {
			continue
		}
		if sendSenderKey(id, payload) {
			sent++
		} else {
			failed++
		}
	}

	if failed > 0 {
		tuiPrintf("[WARN] Sent group key v%d to %d members, %d could not be reached", epoch, sent, failed)
		return
	}
	log.Printf("[DEBUG] distributeSenderKey: group %x epoch %d to %d members", groupID[:4], epoch, sent)
}

// sendSenderKey delivers one chain key to one member, encrypted to them alone
// over the direct conversation the two share.
func sendSenderKey(peerID [16]byte, payload []byte) bool {
	pkt := common.Packet{
		Header: common.Header{
			MsgType:        common.CtrlSenderKey,
			ConversationID: common.HashIDs(mgr.UserID, peerID),
			MessageID:      genID(),
			SenderID:       mgr.UserID,
			BodyLen:        uint32(len(payload)),
		},
		Body: payload,
	}
	if err := sessionMgr.EncryptPacket(&pkt); err != nil {
		log.Printf("[ERROR] Could not seal sender key for %x: %v", peerID[:4], err)
		return false
	}
	if err := sendPacket(&pkt); err != nil {
		log.Printf("[ERROR] Could not send sender key to %x: %v", peerID[:4], err)
		return false
	}
	return true
}
