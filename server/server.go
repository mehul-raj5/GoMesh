package main

import (
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
)

type User struct {
	ID          [common.IDSize]byte
	Username    string
	IdentityKey [32]byte

	// Bundle is the public prekey material handed to anyone opening a chat with
	// this user. IdentityKey is kept alongside it because the group paths still
	// read it directly. The server never holds a private half of anything here.
	Bundle common.PreKeyBundle

	OfflineQueue []common.Packet
}

// sendBufferSize bounds how far a recipient may fall behind before the server
// treats it as a stalled consumer. writeTimeout bounds a single socket write so
// a wedged peer cannot park the write loop forever.
const (
	sendBufferSize  = 128
	writeTimeout    = 10 * time.Second
	maxOfflineQueue = 512
)

// Client owns one connection. Exactly one goroutine (writeLoop) ever writes to
// Conn, so packets are framed in order and no write lock is needed. Producers
// hand packets over via enqueue, which never blocks.
type Client struct {
	Conn     net.Conn
	UserID   [common.IDSize]byte
	Username string

	send      chan common.Packet
	done      chan struct{}
	sendMu    sync.Mutex // guards closed; never held across I/O
	closed    bool
	closeOnce sync.Once
}

// enqueue queues p for delivery. It reports false if the connection is closing
// or the peer has fallen sendBufferSize packets behind.
func (c *Client) enqueue(p common.Packet) bool {
	c.sendMu.Lock()
	defer c.sendMu.Unlock()
	if c.closed {
		return false
	}
	select {
	case c.send <- p:
		return true
	default:
		return false
	}
}

// close tears the connection down. Marking closed under sendMu before closing
// done guarantees no enqueue can land after a spill has drained the channel.
func (c *Client) close() {
	c.closeOnce.Do(func() {
		c.sendMu.Lock()
		c.closed = true
		c.sendMu.Unlock()
		close(c.done)
		c.Conn.Close()
	})
}

type Conversation struct {
	ID      [common.IDSize]byte
	Name    string
	Members [][common.IDSize]byte
	IsGroup bool

	// Membership and Log are the group's signed history. The server orders
	// changes and refuses invalid ones, but clients verify them again, so a
	// compromised server cannot add itself. Members mirrors Membership. Both are
	// guarded by Server.mu, and changeMu serializes submissions to one group so
	// that its broadcasts leave in log order.
	Membership common.Membership
	Log        []common.SignedChange
	changeMu   sync.Mutex
}

func (c *Conversation) HasMember(id [common.IDSize]byte) bool {
	for _, m := range c.Members {
		if m == id {
			return true
		}
	}
	return false
}

func (c *Conversation) RemoveMember(id [common.IDSize]byte) {
	for i, m := range c.Members {
		if m == id {
			c.Members = append(c.Members[:i], c.Members[i+1:]...)
			return
		}
	}
}

type Server struct {
	mu        sync.RWMutex
	users     map[[common.IDSize]byte]*User
	usernames map[string][common.IDSize]byte
	clients   map[[common.IDSize]byte]*Client
	conns     map[net.Conn]*Client
	convs     map[[common.IDSize]byte]*Conversation
	media     SupabaseConfig
}

func NewServer() *Server {
	return &Server{
		users:     make(map[[common.IDSize]byte]*User),
		usernames: make(map[string][common.IDSize]byte),
		clients:   make(map[[common.IDSize]byte]*Client),
		conns:     make(map[net.Conn]*Client),
		convs:     make(map[[common.IDSize]byte]*Conversation),
	}
}

func (s *Server) Start(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	log.Printf("Server listening on %s", addr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("Accept error: %v", err)
			continue
		}
		go s.handleConnection(conn)
	}
}

func (s *Server) handleConnection(conn net.Conn) {
	defer conn.Close()
	defer s.removeConnection(conn)

	p, err := common.Decode(conn)
	if err != nil {
		log.Printf("Handshake decode error: %v", err)
		return
	}

	if p.Header.MsgType != common.CtrlLogin {
		log.Printf("Expected CtrlLogin, got %d", p.Header.MsgType)
		return
	}

	bundle, username, err := common.DecodeLogin(p.Body)
	if err != nil {
		log.Printf("Login payload malformed: %v", err)
		return
	}
	log.Printf("Login: %s", username)

	reject := func() {
		errPkt := common.Packet{Header: common.Header{MsgType: common.CtrlError}}
		errPkt.Encode(conn)
	}

	// A bundle that does not verify never earns a challenge.
	if !bundle.Verify() {
		log.Printf("Login rejected for %s: invalid prekey bundle", username)
		reject()
		return
	}
	if err := s.proveKeyPossession(conn, username, bundle); err != nil {
		log.Printf("Login rejected for %s: %v", username, err)
		reject()
		return
	}

	userID, err := s.authenticateUser(username, bundle)
	if err != nil {
		log.Printf("Login rejected for %s: %v", username, err)
		reject()
		return
	}

	client := &Client{
		Conn:     conn,
		UserID:   userID,
		Username: username,
		send:     make(chan common.Packet, sendBufferSize),
		done:     make(chan struct{}),
	}
	defer client.close()

	ack := common.Packet{
		Header: common.Header{
			MsgType: common.CtrlLoginAck,
			BodyLen: common.IDSize,
		},
		Body: userID[:],
	}

	// Written inline: the write loop has not started and the client is not yet
	// registered, so nothing else can be writing to this socket.
	if err := ack.Encode(conn); err != nil {
		return
	}

	s.addConnection(conn, client)
	go s.writeLoop(client)

	for {
		p, err := common.Decode(conn)
		if err != nil {
			if err != io.EOF {
				log.Printf("Read error for %s: %v", username, err)
			}
			break
		}
		p.Header.SenderID = userID
		s.handlePacket(client, p)
	}
}

// loginProofTimeout bounds how long a connection may sit on a challenge. The
// socket has no other deadline at this stage, so without it an unanswered
// challenge would hold a goroutine for as long as the peer cared to stay quiet.
const loginProofTimeout = 10 * time.Second

// proveKeyPossession issues a fresh challenge and checks the reply against the
// signing key in the bundle. That is enough on its own for a new account, which
// shows the registrant holds the key it is registering, and for a returning one
// authenticateUser then insists the key is the one pinned at first login.
func (s *Server) proveKeyPossession(conn net.Conn, username string, b common.PreKeyBundle) error {
	var nonce [common.LoginNonceSize]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	challenge := common.Packet{
		Header: common.Header{MsgType: common.CtrlLoginChallenge, BodyLen: common.LoginNonceSize},
		Body:   nonce[:],
	}
	if err := challenge.Encode(conn); err != nil {
		return err
	}

	conn.SetReadDeadline(time.Now().Add(loginProofTimeout))
	defer conn.SetReadDeadline(time.Time{})

	proof, err := common.Decode(conn)
	if err != nil {
		return fmt.Errorf("no login proof: %w", err)
	}
	if proof.Header.MsgType != common.CtrlLoginProof || len(proof.Body) != common.SignatureSize {
		return errors.New("malformed login proof")
	}
	var sig [common.SignatureSize]byte
	copy(sig[:], proof.Body)
	if !common.VerifyLogin(b.SigningKey, nonce, b.IdentityKey, username, sig) {
		return errors.New("login proof does not verify")
	}
	return nil
}

func (s *Server) handlePacket(sender *Client, p common.Packet) {
	switch p.Header.MsgType {
	case common.CtrlGroupCreate:
		s.handleGroupCreate(sender, p)
	case common.CtrlGroupChange:
		s.handleGroupChange(sender, p)
	case common.CtrlGroupLogRq:
		s.handleGroupLogRq(sender, p)
	case common.CtrlUserLookupRq:
		s.handleUserLookup(sender, p)
	case common.CtrlDirectInit:
		s.handleDirectInit(sender, p)
	case common.CtrlConvInfoRq:
		s.handleConvInfoRq(sender, p)
	case common.CtrlUploadRq:
		s.handleUploadRq(sender, p)
	case common.CtrlDownloadRq:
		s.handleDownloadRq(sender, p)
	// CtrlSenderKey is a unicast relay: one member's chain key, encrypted to a
	// single peer over the 1-1 conversation they share, so it routes like data.
	case common.MsgText, common.MsgMediaMeta, common.CtrlSenderKey:
		s.handleData(sender, p)
	default:
		log.Printf("Unknown MsgType: %d", p.Header.MsgType)
	}
}

func (s *Server) handleData(sender *Client, p common.Packet) {
	s.mu.RLock()
	conv, ok := s.convs[p.Header.ConversationID]
	var isMember bool
	var members [][common.IDSize]byte
	if ok {
		members = append(members, conv.Members...)
		isMember = conv.HasMember(sender.UserID)
	}
	s.mu.RUnlock()

	if !ok {
		log.Printf("[DEBUG] handleData: Dropped packet type %d for unknown conv %x", p.Header.MsgType, p.Header.ConversationID)
		return
	}

	if !isMember {
		log.Printf("[WARNING] handleData: non-member %x sent to conv %x", sender.UserID[:4], p.Header.ConversationID[:4])
		return
	}

	// A sender key is addressed to one person, so it is only relayed over a
	// two-party conversation and never fanned out to a group.
	if p.Header.MsgType == common.CtrlSenderKey && conv.IsGroup {
		log.Printf("[WARNING] handleData: sender key sent to group %x by %x", p.Header.ConversationID[:4], sender.UserID[:4])
		return
	}

	// members is a snapshot taken under the read lock; enqueue never blocks, so
	// the fan-out runs inline rather than spawning a goroutine per recipient.
	for _, memberID := range members {
		if memberID == sender.UserID {
			continue
		}
		s.sendPacket(memberID, p)
	}
}

// ensurePairwiseConvsLocked registers the 1-1 conversation between every pair of
// members. Group sender keys travel over those direct channels, and handleData
// relays only for conversations the server knows about, so without this every
// pair of members would have to exchange a CtrlDirectInit before the group
// could be keyed at all.
//
// Caller must hold s.mu.Lock.
func (s *Server) ensurePairwiseConvsLocked(members [][common.IDSize]byte) {
	for i := 0; i < len(members); i++ {
		for j := i + 1; j < len(members); j++ {
			convID := common.HashIDs(members[i], members[j])
			if _, exists := s.convs[convID]; exists {
				continue
			}
			s.convs[convID] = &Conversation{
				ID:      convID,
				Members: [][common.IDSize]byte{members[i], members[j]},
				IsGroup: false,
			}
		}
	}
}

func (s *Server) handleDirectInit(sender *Client, p common.Packet) {
	targetName := string(p.Body)

	s.mu.RLock()
	targetID, idExists := s.usernames[targetName]
	var targetUser *User
	if idExists {
		targetUser = s.users[targetID]
	}
	s.mu.RUnlock()

	if !idExists || targetUser.IdentityKey == [32]byte{} {
		log.Printf("[WARNING] Cannot init direct with unregistered user %s", targetName)
		return
	}
	convID := common.HashIDs(sender.UserID, targetID)

	log.Printf("[DEBUG] handleDirectInit: %s (%x) -> %s (%x). ConvID: %x", sender.Username, sender.UserID, targetName, targetID, convID)

	s.mu.Lock()
	_, exists := s.convs[convID]
	if !exists {
		conv := &Conversation{
			ID:      convID,
			Members: make([][common.IDSize]byte, 0),
			IsGroup: false,
		}
		conv.Members = append(conv.Members, sender.UserID)
		conv.Members = append(conv.Members, targetID)
		s.convs[convID] = conv
	}

	var targetBundle common.PreKeyBundle
	if u, ok := s.users[targetID]; ok {
		targetBundle = u.Bundle
	}

	s.mu.Unlock()

	// The target is deliberately not notified. They learn of the conversation
	// when the first message arrives and ask for the roster themselves, which
	// is what lets the initiator start sending while the target is offline.
	//
	// The target's user ID has to be here: the initiator needs it to decide
	// which direction it owns, and it cannot be recovered from the conversation
	// ID, which is a hash. The bundle is what the initiator opens the session
	// with; it checks the prekey signature itself rather than trusting this relay.
	ackBody := make([]byte, 0, 16+16+common.PreKeyBundleSize+len(targetName))
	ackBody = append(ackBody, convID[:]...)
	ackBody = append(ackBody, targetID[:]...)
	ackBody = append(ackBody, targetBundle.Encode()...)
	ackBody = append(ackBody, []byte(targetName)...)

	ack := common.Packet{
		Header: common.Header{
			MsgType:        common.CtrlDirectAck,
			ConversationID: convID,
			BodyLen:        uint32(len(ackBody)),
		},
		Body: ackBody,
	}
	s.sendPacket(sender.UserID, ack)
}

// handleConvInfoRq answers a member's request for the roster of a conversation
// they belong to: whether it is a group, and every member's identity key and
// name. This is the only route by which a client obtains another user's public
// key, so the membership check is what stops it being an open directory of
// every key the server holds.
//
// A request from a non-member, or for a conversation that does not exist, is
// dropped without a reply. Answering differently would tell a prober which
// conversation IDs are real.
func (s *Server) handleConvInfoRq(sender *Client, p common.Packet) {
	if len(p.Body) < common.IDSize {
		return
	}
	var convID [common.IDSize]byte
	copy(convID[:], p.Body[:common.IDSize])

	s.mu.RLock()
	conv, ok := s.convs[convID]
	if !ok || !conv.HasMember(sender.UserID) {
		s.mu.RUnlock()
		log.Printf("[WARNING] CtrlConvInfoRq from %x for conv %x they are not a member of",
			sender.UserID[:4], convID[:4])
		return
	}

	info := common.ConvInfo{
		ConvID:  convID,
		IsGroup: conv.IsGroup,
		Name:    conv.Name,
		Members: make([]common.ConvMember, 0, len(conv.Members)),
	}
	for _, mID := range conv.Members {
		m := common.ConvMember{UserID: mID}
		if u, ok := s.users[mID]; ok {
			m.PubKey = u.IdentityKey
			m.SigningKey = u.Bundle.SigningKey
			m.Name = u.Username
		}
		info.Members = append(info.Members, m)
	}
	s.mu.RUnlock()

	body := info.Encode()
	s.sendPacket(sender.UserID, common.Packet{
		Header: common.Header{
			MsgType:        common.CtrlConvInfoAck,
			ConversationID: convID,
			BodyLen:        uint32(len(body)),
		},
		Body: body,
	})
}

// isMember reports whether userID belongs to the conversation convID.
func (s *Server) isMember(convID, userID [common.IDSize]byte) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	conv, ok := s.convs[convID]
	if !ok {
		return false
	}
	return conv.HasMember(userID)
}

// mediaAck builds a reply that echoes the request's MessageID so the client can
// correlate it. An empty body signals failure to the client.
func mediaAck(msgType uint8, req common.Packet, body []byte) common.Packet {
	return common.Packet{
		Header: common.Header{
			MsgType:        msgType,
			MessageID:      req.Header.MessageID,
			ConversationID: req.Header.ConversationID,
			BodyLen:        uint32(len(body)),
		},
		Body: body,
	}
}

// handleUploadRq mints a signed Supabase upload URL for a conversation member.
func (s *Server) handleUploadRq(sender *Client, p common.Packet) {
	if !s.media.Enabled() {
		log.Printf("[WARNING] CtrlUploadRq but media storage not configured")
		s.sendPacket(sender.UserID, mediaAck(common.CtrlUploadAck, p, nil))
		return
	}
	if !s.isMember(p.Header.ConversationID, sender.UserID) {
		log.Printf("[WARNING] CtrlUploadRq from non-member %x for conv %x", sender.UserID[:4], p.Header.ConversationID[:4])
		s.sendPacket(sender.UserID, mediaAck(common.CtrlUploadAck, p, nil))
		return
	}

	var rnd [16]byte
	rand.Read(rnd[:])
	objectPath := fmt.Sprintf("%x/%x", p.Header.ConversationID[:], rnd[:])

	url, err := s.media.SignUpload(objectPath)
	if err != nil {
		log.Printf("[ERROR] SignUpload: %v", err)
		s.sendPacket(sender.UserID, mediaAck(common.CtrlUploadAck, p, nil))
		return
	}

	body := common.EncodeSignedURLPayload(objectPath, url)
	s.sendPacket(sender.UserID, mediaAck(common.CtrlUploadAck, p, body))
}

// handleDownloadRq mints a signed Supabase download URL, but only for objects
// that belong to a conversation the requester is a member of.
func (s *Server) handleDownloadRq(sender *Client, p common.Packet) {
	if !s.media.Enabled() {
		s.sendPacket(sender.UserID, mediaAck(common.CtrlDownloadAck, p, nil))
		return
	}
	strs, err := common.DecodeSignedURLPayload(p.Body, 1)
	if err != nil {
		s.sendPacket(sender.UserID, mediaAck(common.CtrlDownloadAck, p, nil))
		return
	}
	objectPath := strs[0]

	// The object path is "<convIDhex>/<random>"; require the requester to both
	// name that conversation and be a member of it.
	prefix := fmt.Sprintf("%x/", p.Header.ConversationID[:])
	if !strings.HasPrefix(objectPath, prefix) || !s.isMember(p.Header.ConversationID, sender.UserID) {
		log.Printf("[WARNING] CtrlDownloadRq from %x for foreign object %q", sender.UserID[:4], objectPath)
		s.sendPacket(sender.UserID, mediaAck(common.CtrlDownloadAck, p, nil))
		return
	}

	url, err := s.media.SignDownload(objectPath, 3600)
	if err != nil {
		log.Printf("[ERROR] SignDownload: %v", err)
		s.sendPacket(sender.UserID, mediaAck(common.CtrlDownloadAck, p, nil))
		return
	}

	body := common.EncodeSignedURLPayload(url)
	s.sendPacket(sender.UserID, mediaAck(common.CtrlDownloadAck, p, body))
}

// writeLoop is the sole writer for one connection. It first drains whatever
// accumulated while the user was offline, then serves live traffic. On any
// write failure it tears the connection down and spills the backlog back onto
// the offline queue so nothing is silently dropped.
func (s *Server) writeLoop(c *Client) {
	defer func() {
		c.close()
		s.spill(c)
	}()

	for _, p := range s.takeOfflineQueue(c.UserID) {
		if !s.writePacket(c, p) {
			return
		}
	}

	for {
		select {
		case p := <-c.send:
			if !s.writePacket(c, p) {
				return
			}
		case <-c.done:
			return
		}
	}
}

// writePacket performs one bounded socket write. A false return means the
// connection is finished.
func (s *Server) writePacket(c *Client, p common.Packet) bool {
	c.Conn.SetWriteDeadline(time.Now().Add(writeTimeout))
	if err := p.Encode(c.Conn); err != nil {
		log.Printf("[WARNING] Write to %s (%x) failed: %v", c.Username, c.UserID[:4], err)
		s.queueOffline(c.UserID, p)
		return false
	}
	return true
}

// spill moves anything still queued for a dead connection onto the offline
// queue. Safe because close() marks the client closed before this runs, so no
// further enqueue can succeed.
func (s *Server) spill(c *Client) {
	for {
		select {
		case p := <-c.send:
			s.queueOffline(c.UserID, p)
		default:
			return
		}
	}
}

// queueOffline stores a packet for later delivery, capped at maxOfflineQueue
// packets per user; the oldest are discarded first.
func (s *Server) queueOffline(userID [common.IDSize]byte, p common.Packet) {
	s.mu.Lock()
	defer s.mu.Unlock()
	user, ok := s.users[userID]
	if !ok {
		return
	}
	if len(user.OfflineQueue) >= maxOfflineQueue {
		drop := len(user.OfflineQueue) - maxOfflineQueue + 1
		log.Printf("[WARNING] Offline queue full for %x, dropping %d oldest", userID[:4], drop)
		user.OfflineQueue = append(user.OfflineQueue[:0], user.OfflineQueue[drop:]...)
	}
	user.OfflineQueue = append(user.OfflineQueue, p)
}

func (s *Server) sendPacket(userID [common.IDSize]byte, p common.Packet) {
	s.mu.RLock()
	client, ok := s.clients[userID]
	s.mu.RUnlock()

	if !ok {
		s.queueOffline(userID, p)
		return
	}

	if !client.enqueue(p) {
		log.Printf("[WARNING] %s (%x) is not keeping up; disconnecting", client.Username, userID[:4])
		client.close() // its writeLoop spills the rest
		s.queueOffline(userID, p)
	}
}

// takeOfflineQueue atomically removes and returns a user's queued packets.
func (s *Server) takeOfflineQueue(userID [common.IDSize]byte) []common.Packet {
	s.mu.Lock()
	defer s.mu.Unlock()
	user, ok := s.users[userID]
	if !ok || len(user.OfflineQueue) == 0 {
		return nil
	}
	queue := user.OfflineQueue
	user.OfflineQueue = nil
	return queue
}

// authenticateUser registers a new username or admits a returning one.
//
// A bundle whose prekey signature does not check out is refused outright, so
// the server never hands out a prekey that its own signing key did not vouch
// for. The identity and signing keys are pinned on first use, as the identity
// key always was: a returning user must present both unchanged. The signed
// prekey alone may change between logins, which is how a client rotates it, and
// the latest valid one wins.
func (s *Server) authenticateUser(username string, bundle common.PreKeyBundle) ([common.IDSize]byte, error) {
	if !bundle.Verify() {
		return [common.IDSize]byte{}, errors.New("invalid prekey bundle")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if id, ok := s.usernames[username]; ok {
		if u, exists := s.users[id]; exists {
			if u.IdentityKey != bundle.IdentityKey || u.Bundle.SigningKey != bundle.SigningKey {
				return [common.IDSize]byte{}, errors.New("username already taken")
			}
			u.Bundle = bundle
		}
		return id, nil
	}

	id := genID()
	s.usernames[username] = id
	s.users[id] = &User{
		ID:           id,
		Username:     username,
		IdentityKey:  bundle.IdentityKey,
		Bundle:       bundle,
		OfflineQueue: make([]common.Packet, 0),
	}
	return id, nil
}

func (s *Server) getUserIDByName(username string) ([common.IDSize]byte, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.usernames[username]
	return id, ok
}

func (s *Server) addConnection(conn net.Conn, client *Client) {
	s.mu.Lock()
	if oldClient, ok := s.clients[client.UserID]; ok {
		// Close the old connection to prevent ghost sessions
		oldClient.close()
		delete(s.conns, oldClient.Conn)
	}
	s.clients[client.UserID] = client
	s.conns[conn] = client
	s.mu.Unlock()
}

func (s *Server) removeConnection(conn net.Conn) {
	s.mu.Lock()
	if client, ok := s.conns[conn]; ok {
		delete(s.conns, conn)
		// Only delete from clients map if this connection is the currently active one
		// otherwise, we might be deleting a newly established connection (if old conn just closed)
		if activeClient, isClientOk := s.clients[client.UserID]; isClientOk && activeClient.Conn == conn {
			delete(s.clients, client.UserID)
		}
	}
	s.mu.Unlock()
}

func genID() [16]byte {
	var id [16]byte
	if _, err := io.ReadFull(rand.Reader, id[:]); err != nil {
		panic(err)
	}
	return id
}

func main() {
	srv := NewServer()

	srv.media = SupabaseConfig{
		URL:        strings.TrimRight(os.Getenv("SUPABASE_URL"), "/"),
		ServiceKey: os.Getenv("SUPABASE_SERVICE_KEY"),
		Bucket:     os.Getenv("SUPABASE_BUCKET"),
	}
	if srv.media.Enabled() {
		log.Printf("Media storage enabled (bucket %q at %s)", srv.media.Bucket, srv.media.URL)
	} else {
		log.Printf("Media storage DISABLED: set SUPABASE_URL, SUPABASE_SERVICE_KEY, SUPABASE_BUCKET to enable")
	}

	addr := os.Getenv("LISTEN_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	if err := srv.Start(addr); err != nil {
		log.Fatal(err)
	}
}
