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
	sessionMgr.OnReplaced = onSessionReplaced
	sessionMgr.SigningPin = knownSigning
	restoreSessions()
	restoreGroups()

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

		if errors.Is(err, ErrNoGroupSession) || errors.Is(err, ErrNoSenderKey) || errors.Is(err, ErrMembershipBehind) {
			pending.ParkFor(convID, pkt, GroupPendingTTL)
		} else {
			pending.Park(convID, pkt)
		}

		// A missing sender key is already on its way over the direct channel we
		// share with that member, and a missing epoch is waiting on a packet
		// that is itself in flight, so there is nothing to ask for. Not knowing
		// the conversation at all is different: the roster has to be fetched.
		if errors.Is(err, ErrNoSession) || errors.Is(err, ErrNoGroupSession) {
			requestConvInfo(convID)
		}
		// A message from a membership version we have not seen: fetch the log.
		if errors.Is(err, ErrMembershipBehind) {
			requestGroupLog(convID)
		}
		return
	}

	// A sender key arrives over a 1:1 session that exists for the group's sake, so
	// it does not add a private chat to the list.
	direct := wasEncrypted && !mgr.IsGroup(convID) && !sessionMgr.HasGroup(convID) && pkt.Header.MsgType != common.CtrlSenderKey
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
	convID := pkt.Header.ConversationID
	if mgr.IsGroup(convID) || sessionMgr.HasGroup(convID) {
		return sessionMgr.DecryptGroupPacket(pkt)
	}
	// A group this client has not heard of yet looks like a direct chat. Its body
	// says otherwise, and it is held until the group's log arrives.
	if !mgr.HasConversation(convID) {
		if w, err := common.DecodeGroupWire(pkt.Body); err == nil && w.Header.GroupID == convID {
			return fmt.Errorf("%w: %x", ErrNoGroupSession, convID[:4])
		}
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
				// Starting over means whatever the peer held of our sender keys is gone.
				sessionMgr.PeerKeysChanged(peerID)
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
			handleSenderKey(pkt)

		case common.CtrlGroupChange:
			handleGroupChange(pkt)

		case common.CtrlGroupHints:
			handleGroupHints(pkt)

		case common.CtrlGroupChangeReject:
			handleGroupReject(pkt)

		case common.CtrlUserLookupAck:
			deliverLookup(pkt)

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
	if !info.IsGroup {
		for _, m := range info.Members {
			if m.UserID == mgr.UserID {
				continue
			}
			mgr.AddUser(m.UserID, m.Name)
			mgr.UpdatePublicKey(m.UserID, m.PubKey)
		}
	}

	if info.IsGroup {
		// Who is in a group is what its signed log says, not what this roster says.
		// The roster supplies the name and tells us the conversation is a group;
		// the log, requested here, supplies the members.
		name := info.Name
		if name == "" {
			name = fmt.Sprintf("%x", info.ConvID[:4])
		}
		if !mgr.HasConversation(info.ConvID) || !mgr.IsGroup(info.ConvID) {
			mgr.RegisterConversation(info.ConvID, name, true)
		}
		requestGroupLog(info.ConvID)
		return
	}

	{
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
