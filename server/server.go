package main

import (
	common "common"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"slices"
	"sync"
	"syscall"
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

	PasswordHash string

	// Device is the account's current device. Its offline queue belongs to it,
	// not to the account: when the account moves to new keys the old device is
	// dropped with its queue, and nothing queued for it can reach the new one.
	Device *Device
}

// Device is the keys an account currently signs in with, and the packets
// waiting for them. The queue is mirrored in the store, row for row.
type Device struct {
	ID         [common.IDSize]byte
	Name       string
	Queue      []queued
	QueueBytes int
}

// sendBufferSize bounds how far a recipient may fall behind before the server
// treats it as a stalled consumer. writeTimeout bounds a single socket write so
// a wedged peer cannot park the write loop forever.
const (
	sendBufferSize = 128
	writeTimeout   = 10 * time.Second
)

// A device's offline queue holds at most maxOfflineQueue packets and
// maxQueueBytes of them, and drops the oldest first. Phones are offline far more
// than terminals were, and the queue lives on disk now, so it is both longer
// than it was and bounded in bytes: one sender relaying large bodies must not be
// able to fill the disk. Variables only so tests can lower them.
var (
	maxOfflineQueue = 5000
	maxQueueBytes   = 64 << 20
)

// A connection may have at most maxUnacked packets written and not yet
// acknowledged; past that the server waits for an acknowledgement before it
// writes more, and closes the connection if none comes within ackTimeout. A
// client acknowledges every 64 packets, so a healthy one never waits.
// Variables only so tests can lower them.
var (
	maxUnacked = 1024
	ackTimeout = 60 * time.Second
)

// Client owns one connection. Exactly one goroutine (writeLoop) ever writes to
// Conn, so packets are framed in order and no write lock is needed. Producers
// hand packets over via enqueue, which never blocks.
type Client struct {
	Conn     net.Conn
	UserID   [common.IDSize]byte
	DeviceID [common.IDSize]byte
	Username string

	send      chan common.Packet
	done      chan struct{}
	sendMu    sync.Mutex // guards closed, retired and final; never held across I/O
	closed    bool
	closeOnce sync.Once

	// retired is set when the account moved to another device. final is the
	// notice the write loop sends before closing the connection.
	retired bool
	final   *common.Packet

	// unacked holds the packets written on this connection that the device has
	// not acknowledged yet, oldest first; a seq says the packet still has its row
	// in the store. written and acked count packets since the login. ackSignal
	// wakes a write loop waiting for room, and ended is closed once the
	// connection's write loop has put back everything it did not deliver.
	ackMu     sync.Mutex
	unacked   []queued
	written   uint64
	acked     uint64
	requeued  bool // the unacknowledged went back on the queue; later acks change nothing
	ackSignal chan struct{}
	ended     chan struct{}
}

func newClient(conn net.Conn, userID, deviceID [common.IDSize]byte, username string) *Client {
	return &Client{
		Conn: conn, UserID: userID, DeviceID: deviceID, Username: username,
		send:      make(chan common.Packet, sendBufferSize),
		done:      make(chan struct{}),
		ackSignal: make(chan struct{}, 1),
		ended:     make(chan struct{}),
	}
}

// track records a packet just written, to be kept until it is acknowledged.
func (c *Client) track(q queued) {
	c.ackMu.Lock()
	c.unacked = append(c.unacked, q)
	c.written++
	c.ackMu.Unlock()
}

// holdBack keeps a packet the connection failed to write with the ones it
// wrote, after them, so that all of them go back on the queue in order.
func (c *Client) holdBack(p common.Packet) {
	c.ackMu.Lock()
	c.unacked = append(c.unacked, queued{pkt: p})
	c.ackMu.Unlock()
}

func (c *Client) unackedCount() int {
	c.ackMu.Lock()
	defer c.ackMu.Unlock()
	return len(c.unacked)
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
func (c *Client) close() { c.shutdown(nil) }

// retire ends a connection whose account has moved to another device. Nothing
// more may be queued on it, and its write loop sends notice as the last packet
// and then closes the socket. The notice goes through the write loop because
// that is the connection's only writer; writing it from here could interleave
// it with a packet already on the wire. Delivery is not awaited or retried.
func (c *Client) retire(notice common.Packet) { c.shutdown(&notice) }

func (c *Client) shutdown(final *common.Packet) {
	c.closeOnce.Do(func() {
		c.sendMu.Lock()
		c.closed = true
		if final != nil {
			c.retired = true
			c.final = final
		}
		c.sendMu.Unlock()
		close(c.done)
		if final == nil {
			c.Conn.Close()
		}
	})
}

func (c *Client) isRetired() bool {
	c.sendMu.Lock()
	defer c.sendMu.Unlock()
	return c.retired
}

func (c *Client) takeFinal() *common.Packet {
	c.sendMu.Lock()
	defer c.sendMu.Unlock()
	f := c.final
	c.final = nil
	return f
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

	// lastConn is each device's newest connection. A new one waits for the one
	// before it to put back what it did not deliver, so the new one's drain of
	// the queue includes it. Guarded by mu.
	lastConn map[[common.IDSize]byte]*Client

	store *Store
	tls   *tls.Config
	auth  *authenticator
	ln    net.Listener

	// accountMu serializes changes to accounts (register, a device moving,
	// logout, resume) so the database and the maps above change together. It is
	// never held while a password is hashed.
	accountMu sync.Mutex

	// closed stops new connections from being admitted once Close has begun, and
	// loops counts the read and write loops Close waits for: a write loop spills
	// what it had not sent, and a read loop may be routing a packet into an
	// offline queue. Both are guarded by mu.
	closed bool
	loops  sync.WaitGroup
}

// Close stops accepting connections, drops every connected client and waits
// for their write loops to finish. A write loop spills whatever its client had
// not been sent into the store, so after Close returns nothing is left only in
// memory. The store stays open; whoever opened it closes it.
func (s *Server) Close() {
	s.mu.Lock()
	s.closed = true
	ln := s.ln
	clients := make([]*Client, 0, len(s.conns))
	for _, c := range s.conns {
		clients = append(clients, c)
	}
	s.mu.Unlock()
	if ln != nil {
		ln.Close()
	}
	for _, c := range clients {
		c.close()
	}
	s.loops.Wait()
}

// NewServer builds a server on store and loads the accounts it holds.
func NewServer(store *Store) (*Server, error) {
	s := &Server{
		users:     make(map[[common.IDSize]byte]*User),
		usernames: make(map[string][common.IDSize]byte),
		clients:   make(map[[common.IDSize]byte]*Client),
		conns:     make(map[net.Conn]*Client),
		lastConn:  make(map[[common.IDSize]byte]*Client),
		convs:     make(map[[common.IDSize]byte]*Conversation),
		store:     store,
		auth:      newAuthenticator(defaultAuth),
	}
	recs, err := store.LoadUsers()
	if err != nil {
		return nil, fmt.Errorf("loading accounts: %w", err)
	}
	if n, err := store.DropStaleQueues(); err != nil {
		return nil, fmt.Errorf("pruning queues: %w", err)
	} else if n > 0 {
		log.Printf("Deleted %d queued packet(s) for devices no account uses any more", n)
	}
	for _, r := range recs {
		dev := &Device{ID: r.DeviceID, Name: r.DeviceName}
		q, err := store.LoadQueue(r.DeviceID)
		if err != nil {
			return nil, fmt.Errorf("loading %s's queue: %w", r.Username, err)
		}
		dev.Queue = q
		for _, item := range q {
			dev.QueueBytes += len(item.enc)
		}
		s.users[r.ID] = &User{
			ID:           r.ID,
			Username:     r.Username,
			IdentityKey:  r.Bundle.IdentityKey,
			Bundle:       r.Bundle,
			PasswordHash: r.PasswordHash,
			Device:       dev,
		}
		s.usernames[r.Username] = r.ID
	}

	convs, err := store.LoadConversations()
	if err != nil {
		return nil, fmt.Errorf("loading conversations: %w", err)
	}
	for _, r := range convs {
		c := &Conversation{ID: r.ID, Name: r.Name, IsGroup: r.IsGroup}
		if r.IsGroup {
			// The log is replayed without directory pins. Every entry was checked
			// against the directory when it was accepted, and a pin is a current
			// key, which a log that rekeyed someone does not hold throughout.
			for _, sc := range r.Log {
				if _, err := c.Membership.Apply(&sc, nil); err != nil {
					return nil, fmt.Errorf("group %x does not replay at version %d: %w", r.ID[:4], sc.Change.Version, err)
				}
			}
			c.Log = r.Log
			c.Members = c.Membership.MemberIDs()
		} else {
			c.Members = r.Members
		}
		s.convs[r.ID] = c
	}
	return s, nil
}

// Start listens on addr. Every connection is TLS; there is no plaintext mode,
// because passwords cross it.
func (s *Server) Start(addr string) error {
	if s.tls == nil {
		return errors.New("no TLS certificate configured")
	}
	ln, err := tls.Listen("tcp", addr, s.tls)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.ln = ln
	closing := s.closed
	s.mu.Unlock()
	if closing {
		// Close ran before there was a listener to close.
		ln.Close()
		return nil
	}
	log.Printf("Server listening on %s (TLS)", addr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			log.Printf("Accept error: %v", err)
			continue
		}
		go s.handleConnection(conn)
	}
}

func (s *Server) handleConnection(conn net.Conn) {
	defer conn.Close()
	defer s.removeConnection(conn)

	// One deadline covers the whole login: the TLS handshake, the first packet,
	// the challenge and its proof. Without it a peer that connects and says
	// nothing would hold a goroutine for as long as it liked.
	conn.SetDeadline(time.Now().Add(loginTimeout))
	sess, err := s.authenticate(conn)
	if err != nil {
		if !errors.Is(err, errHungUp) {
			log.Printf("Login from %s refused: %v", remoteIP(conn), err)
		}
		return
	}

	client := newClient(conn, sess.userID, sess.deviceID, sess.username)
	defer client.close()

	ackBody := common.EncodeLoginAck(sess.userID, sess.token)
	ack := common.Packet{
		Header: common.Header{MsgType: common.CtrlLoginAck, BodyLen: uint32(len(ackBody))},
		Body:   ackBody,
	}

	// Written inline: the write loop has not started and the client is not yet
	// registered, so nothing else can be writing to this socket.
	if err := ack.Encode(conn); err != nil {
		return
	}
	conn.SetDeadline(time.Time{})

	prev, ok := s.admit(conn, client)
	if !ok {
		return // shutting down
	}
	s.sendMyGroups(sess.userID)
	go func() {
		awaitEnded(prev)
		s.writeLoop(client)
	}()
	s.readLoop(client)
	s.loops.Done()
}

// readLoop handles what an authenticated client sends until it disconnects.
func (s *Server) readLoop(client *Client) {
	for {
		p, err := common.Decode(client.Conn)
		if err != nil {
			if err != io.EOF {
				log.Printf("Read error for %s: %v", client.Username, err)
			}
			return
		}
		// A device that has been replaced may still have packets in flight. They
		// are not the account's any more, so they are dropped; its write loop is
		// closing the socket.
		if client.isRetired() {
			continue
		}
		if p.Header.MsgType == common.CtrlDelivered {
			s.acknowledge(client, p.Body)
			continue
		}
		if p.Header.MsgType == common.CtrlLogout {
			s.logout(client)
			return
		}
		p.Header.SenderID = client.UserID
		s.handlePacket(client, p)
	}
}

// loginTimeout bounds the whole login exchange, including a password hash that
// may have to wait for a free slot.
var loginTimeout = 30 * time.Second

// proveKeyPossession issues a fresh challenge and checks the reply against the
// signing key in the bundle. For a new account that shows the registrant holds
// the key it is registering; for a returning one it shows the device holds the
// keys it presents. The password, checked before this, is what ties either to
// the account.
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

	proof, err := common.DecodeMax(conn, common.MaxPreAuthBody)
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
	case common.CtrlReceiptsRq:
		s.handleReceiptsRq(sender, p)
	// CtrlSenderKey is a unicast relay: one member's chain key, encrypted to a
	// single peer over the 1-1 conversation they share, so it routes like data.
	case common.MsgText, common.MsgMediaMeta, common.CtrlSenderKey, common.CtrlSessionReset, common.MsgReadReceipt:
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

	// A sender key, a session reset or a read receipt is addressed to one person,
	// so it is only relayed over a two-party conversation and never fanned out
	// to a group.
	if (p.Header.MsgType == common.CtrlSenderKey || p.Header.MsgType == common.CtrlSessionReset ||
		p.Header.MsgType == common.MsgReadReceipt) &&
		(conv.IsGroup || len(conv.Members) != 2) {
		log.Printf("[WARNING] handleData: type %#x sent to group %x by %x", p.Header.MsgType, p.Header.ConversationID[:4], sender.UserID[:4])
		return
	}

	// members is a snapshot taken under the read lock; enqueue never blocks, so
	// the fan-out runs inline rather than spawning a goroutine per recipient.
	var recipients [][common.IDSize]byte
	for _, memberID := range members {
		if memberID != sender.UserID {
			recipients = append(recipients, memberID)
		}
	}
	if hasReceipts(p.Header.MsgType) {
		s.reportAccepted(sender, p, recipients)
	}
	for _, memberID := range recipients {
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
// persistDirectLocked records a two-party conversation, made by a /dm or for a
// group, which come to the same ID for the same pair. A failure is logged and
// the conversation still works until the server restarts. Caller holds s.mu.
func (s *Server) persistDirectLocked(convID [common.IDSize]byte, members [][common.IDSize]byte) {
	if s.store == nil {
		return
	}
	if err := s.store.SaveDirect(convID, members); err != nil {
		log.Printf("[ERROR] could not store conversation %x: %v", convID[:4], err)
	}
}

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
			s.persistDirectLocked(convID, s.convs[convID].Members)
		}
	}
}

func (s *Server) handleDirectInit(sender *Client, p common.Packet) {
	targetName := strings.ToLower(string(p.Body))

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
		s.persistDirectLocked(convID, conv.Members)
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
// accumulated while the device was offline, then serves live traffic. On any
// write failure it tears the connection down and spills the backlog back onto
// the device's offline queue so nothing is silently dropped. A retired client
// instead writes its final notice and stops; its backlog is discarded by the
// spill, because its device no longer exists.
func (s *Server) writeLoop(c *Client) {
	defer func() {
		c.close()
		c.Conn.Close()
		s.requeueUnacked(c)
		s.spill(c)
		s.connEnded(c)
		s.loops.Done()
	}()

	if !s.drainQueue(c) {
		return
	}

	for {
		// Shutting down takes precedence over the backlog, so a retired client's
		// notice is not held behind packets for a device that no longer exists.
		if s.finished(c) {
			return
		}
		select {
		case p := <-c.send:
			if !s.writePacket(c, p) {
				return
			}
		case <-c.done:
			s.finished(c)
			return
		}
	}
}

// drainQueue sends a device what waited for it while it was offline. A row is
// deleted from the store only once the device acknowledges its packet, and
// exactly that row, so a crash or a dropped connection part way through
// delivers the rest again rather than losing it; clients ignore what they have
// already read. Whatever is not written goes back on the queue, whichever way
// the drain ends. It reports false if the connection is finished.
func (s *Server) drainQueue(c *Client) bool {
	queue := s.takeOfflineQueue(c.UserID, c.DeviceID)
	for i, q := range queue {
		if s.finished(c) || !s.awaitWindow(c) || !s.writeOnce(c, q.pkt) {
			s.putBack(c, queue[i:])
			return false
		}
		c.track(q)
	}
	return true
}

// awaitWindow waits until the connection has room for another unacknowledged
// packet. It reports false if the connection is finished, or if the device
// stopped acknowledging; the connection is then closed.
func (s *Server) awaitWindow(c *Client) bool {
	if c.ackSignal == nil {
		return true
	}
	var timeout <-chan time.Time
	for c.unackedCount() >= maxUnacked {
		if timeout == nil {
			t := time.NewTimer(ackTimeout)
			defer t.Stop()
			timeout = t.C
		}
		select {
		case <-c.ackSignal:
		case <-c.done:
			return false
		case <-timeout:
			log.Printf("[WARNING] %s (%x) acknowledged nothing for %v; disconnecting", c.Username, c.UserID[:4], ackTimeout)
			return false
		}
	}
	return true
}

// acknowledge handles a device's count of the packets it has handled on this
// connection: the packets it covers are delivered, and their rows deleted.
func (s *Server) acknowledge(c *Client, body []byte) {
	n, err := common.DecodeDelivered(body)
	if err != nil {
		log.Printf("[WARNING] %s (%x): %v", c.Username, c.UserID[:4], err)
		return
	}
	c.ackMu.Lock()
	if c.requeued {
		// The write loop has finished and put everything back; the read loop
		// can still be reading. What this covers will be delivered again.
		c.ackMu.Unlock()
		return
	}
	if n < c.acked || n > c.written {
		c.ackMu.Unlock()
		log.Printf("[WARNING] %s (%x) acknowledged %d packets; %d were written", c.Username, c.UserID[:4], n, c.written)
		return
	}
	k := int(n - c.acked)
	var seqs []int64
	var handled []common.Packet
	for _, q := range c.unacked[:k] {
		if q.seq != 0 {
			seqs = append(seqs, q.seq)
		}
		if hasReceipts(q.pkt.Header.MsgType) {
			handled = append(handled, q.pkt)
		}
	}
	c.unacked = slices.Delete(c.unacked, 0, k)
	c.acked = n
	c.ackMu.Unlock()
	s.dequeue(seqs)
	for _, p := range handled {
		s.reportDelivered(c.UserID, p)
	}
	select {
	case c.ackSignal <- struct{}{}:
	default:
	}
}

// requeueUnacked puts back what a finished connection wrote but never had
// acknowledged, ahead of what it had not written yet. Packets from the queue
// still have their rows; live ones are stored now, except replies, which only
// meant something to that connection.
func (s *Server) requeueUnacked(c *Client) {
	c.ackMu.Lock()
	items := c.unacked
	c.unacked = nil
	c.requeued = true
	c.ackMu.Unlock()
	var stored []queued
	for _, q := range items {
		if q.seq != 0 {
			stored = append(stored, q)
		}
	}
	s.putBack(c, stored)
	for _, q := range items {
		if q.seq == 0 && !common.IsReply(q.pkt.Header.MsgType) {
			s.queueOffline(c.UserID, c.DeviceID, q.pkt)
		}
	}
}

// connEnded marks a connection's write loop finished, everything undelivered
// put back.
func (s *Server) connEnded(c *Client) {
	s.mu.Lock()
	if s.lastConn[c.DeviceID] == c {
		delete(s.lastConn, c.DeviceID)
	}
	s.mu.Unlock()
	if c.ended != nil {
		close(c.ended)
	}
}

// awaitEnded waits, for a while, for an earlier connection of the same device
// to put back what it did not deliver. Its socket is already closed, so this is
// quick; the bound is a backstop.
func awaitEnded(prev *Client) {
	if prev == nil || prev.ended == nil {
		return
	}
	select {
	case <-prev.ended:
	case <-time.After(writeTimeout):
		log.Printf("[WARNING] %s (%x): the previous connection took too long to finish", prev.Username, prev.UserID[:4])
	}
}

// writeOnce performs one bounded socket write and nothing else.
func (s *Server) writeOnce(c *Client, p common.Packet) bool {
	c.Conn.SetWriteDeadline(time.Now().Add(writeTimeout))
	if err := p.Encode(c.Conn); err != nil {
		log.Printf("[WARNING] Write to %s (%x) failed: %v", c.Username, c.UserID[:4], err)
		return false
	}
	return true
}

// putBack returns unsent packets to the front of their device's queue. They
// still have their rows, so nothing is written to the store. If the device has
// been replaced meanwhile they are dropped: the move deleted their rows.
func (s *Server) putBack(c *Client, items []queued) {
	if len(items) == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	user, ok := s.users[c.UserID]
	if !ok || user.Device == nil || user.Device.ID != c.DeviceID {
		return
	}
	d := user.Device
	for _, q := range items {
		d.QueueBytes += len(q.enc)
	}
	d.Queue = append(append([]queued(nil), items...), d.Queue...)
}

func (s *Server) dequeue(seqs []int64) {
	if s.store == nil || len(seqs) == 0 {
		return
	}
	if err := s.store.Dequeue(seqs); err != nil {
		log.Printf("[ERROR] could not delete %d delivered packet(s) from the store: %v", len(seqs), err)
	}
}

// finished reports whether c is shutting down, writing its final notice first
// if it has one.
func (s *Server) finished(c *Client) bool {
	select {
	case <-c.done:
	default:
		return false
	}
	if f := c.takeFinal(); f != nil {
		c.Conn.SetWriteDeadline(time.Now().Add(finalNoticeTimeout))
		f.Encode(c.Conn)
	}
	return true
}

// finalNoticeTimeout bounds the one write a retired connection still makes.
const finalNoticeTimeout = 2 * time.Second

// writePacket performs one bounded socket write, once there is room for
// another unacknowledged packet. A false return means the connection is
// finished; the packet is put back with the unacknowledged ones, after them.
func (s *Server) writePacket(c *Client, p common.Packet) bool {
	if !s.awaitWindow(c) {
		c.holdBack(p)
		return false
	}
	c.Conn.SetWriteDeadline(time.Now().Add(writeTimeout))
	if err := p.Encode(c.Conn); err != nil {
		log.Printf("[WARNING] Write to %s (%x) failed: %v", c.Username, c.UserID[:4], err)
		c.holdBack(p)
		return false
	}
	c.track(queued{pkt: p})
	return true
}

// spill moves anything still queued for a dead connection onto its device's
// offline queue. Safe because close() marks the client closed before this
// runs, so no further enqueue can succeed.
func (s *Server) spill(c *Client) {
	for {
		select {
		case p := <-c.send:
			s.queueOffline(c.UserID, c.DeviceID, p)
		default:
			return
		}
	}
}

// queueOffline stores a packet for later delivery to one device, capped at
// maxOfflineQueue packets; the oldest are discarded first. A packet for a
// device the account no longer uses is dropped: whatever path it comes back by
// (a spill, a failed write), it must never land in the new device's queue.
func (s *Server) queueOffline(userID, deviceID [common.IDSize]byte, p common.Packet) {
	s.mu.Lock()
	defer s.mu.Unlock()
	user, ok := s.users[userID]
	if !ok || user.Device == nil || user.Device.ID != deviceID {
		return
	}
	s.appendQueueLocked(user.Device, userID, p)
}

// queueForUser stores a packet for whichever device the account uses now.
func (s *Server) queueForUser(userID [common.IDSize]byte, p common.Packet) {
	s.mu.Lock()
	defer s.mu.Unlock()
	user, ok := s.users[userID]
	if !ok || user.Device == nil {
		return
	}
	s.appendQueueLocked(user.Device, userID, p)
}

// appendQueueLocked stores a packet for a device, in memory and in the store,
// dropping the oldest to stay within the count and byte limits. Caller holds s.mu.
func (s *Server) appendQueueLocked(d *Device, userID [common.IDSize]byte, p common.Packet) {
	q := queued{pkt: p, enc: encodePacket(p)}
	if s.store != nil {
		seq, err := s.store.Enqueue(d.ID, q.enc)
		if err != nil {
			log.Printf("[ERROR] could not store a queued packet for %x; it is held in memory only: %v", userID[:4], err)
		}
		q.seq = seq
	}
	d.Queue = append(d.Queue, q)
	d.QueueBytes += len(q.enc)

	var dropped []int64
	n := 0
	for len(d.Queue) > 1 && (len(d.Queue) > maxOfflineQueue || d.QueueBytes > maxQueueBytes) {
		old := d.Queue[0]
		d.Queue = d.Queue[1:]
		d.QueueBytes -= len(old.enc)
		if old.seq != 0 {
			dropped = append(dropped, old.seq)
		}
		n++
	}
	if n > 0 {
		log.Printf("[WARNING] Offline queue full for %x, dropped the %d oldest", userID[:4], n)
		s.dequeue(dropped)
	}
}

func (s *Server) sendPacket(userID [common.IDSize]byte, p common.Packet) {
	s.mu.RLock()
	client, ok := s.clients[userID]
	s.mu.RUnlock()

	if !ok {
		s.queueForUser(userID, p)
		return
	}

	if !client.enqueue(p) {
		if !client.isRetired() {
			log.Printf("[WARNING] %s (%x) is not keeping up; disconnecting", client.Username, userID[:4])
			client.close() // its writeLoop spills the rest
		}
		// Addressed to the account, so it waits for whichever device is current.
		s.queueForUser(userID, p)
	}
}

// takeOfflineQueue atomically removes and returns the packets queued for a
// device. It returns nothing if the account has since moved to another one. The
// rows stay in the store until the packets have been written.
func (s *Server) takeOfflineQueue(userID, deviceID [common.IDSize]byte) []queued {
	s.mu.Lock()
	defer s.mu.Unlock()
	user, ok := s.users[userID]
	if !ok || user.Device == nil || user.Device.ID != deviceID || len(user.Device.Queue) == 0 {
		return nil
	}
	queue := user.Device.Queue
	user.Device.Queue, user.Device.QueueBytes = nil, 0
	return queue
}

func (s *Server) getUserIDByName(username string) ([common.IDSize]byte, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.usernames[strings.ToLower(username)]
	return id, ok
}

// addConnection admits an authenticated client and counts its two loops, unless
// the server is shutting down.
func (s *Server) addConnection(conn net.Conn, client *Client) bool {
	_, ok := s.admit(conn, client)
	return ok
}

// admit registers a signed-in connection and returns the same device's
// previous one, if it may still be putting packets back.
func (s *Server) admit(conn net.Conn, client *Client) (*Client, bool) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, false
	}
	prev := s.lastConn[client.DeviceID]
	s.lastConn[client.DeviceID] = client
	s.loops.Add(2)
	if oldClient, ok := s.clients[client.UserID]; ok {
		// Close the old connection to prevent ghost sessions. One from a device
		// the account has left was already retired when it moved.
		if oldClient.DeviceID == client.DeviceID {
			oldClient.close()
		} else {
			oldClient.retire(common.ErrorPacket(common.ErrDeviceReplaced, ""))
		}
		delete(s.conns, oldClient.Conn)
	}
	s.clients[client.UserID] = client
	s.conns[conn] = client
	s.mu.Unlock()
	return prev, true
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
	genCert := flag.String("gen-dev-cert", "", "write a self-signed development certificate into `dir` and exit")
	flag.Parse()
	if *genCert != "" {
		if err := writeDevCert(*genCert, flag.Args()); err != nil {
			log.Fatal(err)
		}
		return
	}

	dbPath := envOr("DB_PATH", "gomesh.db")
	store, err := OpenStore(dbPath)
	if err != nil {
		log.Fatalf("Opening %s: %v", dbPath, err)
	}
	srv, err := NewServer(store)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Accounts in %s: %d", dbPath, len(srv.users))

	certFile := envOr("TLS_CERT", filepath.Join("dev-certs", "cert.pem"))
	keyFile := envOr("TLS_KEY", filepath.Join("dev-certs", "key.pem"))
	certPEM, err1 := os.ReadFile(certFile)
	keyPEM, err2 := os.ReadFile(keyFile)
	if err1 != nil || err2 != nil {
		log.Fatalf("No TLS certificate at %s and %s. Run `make dev-cert`, or set TLS_CERT and TLS_KEY.", certFile, keyFile)
	}
	tlsCfg, fingerprint, err := common.ServerTLSConfig(certPEM, keyPEM)
	if err != nil {
		log.Fatalf("Loading the TLS certificate: %v", err)
	}
	srv.tls = tlsCfg
	log.Printf("TLS certificate fingerprint: %s", common.FormatFingerprint(fingerprint))

	// Lower the password-hash cost, for tests only. Production keeps the defaults.
	cfg := defaultAuth
	if v, err := strconv.Atoi(os.Getenv("ARGON2_MEMORY_KIB")); err == nil && v > 0 {
		cfg.Argon.MemoryKiB = uint32(v)
	}
	if v, err := strconv.Atoi(os.Getenv("ARGON2_TIME")); err == nil && v > 0 {
		cfg.Argon.Time = uint32(v)
	}
	if v, err := strconv.Atoi(os.Getenv("AUTH_IP_ATTEMPTS")); err == nil && v > 0 {
		cfg.IPAttempts = v
	}
	srv.auth = newAuthenticator(cfg)

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

	// On SIGINT or SIGTERM, stop cleanly: Close waits for every connection to put
	// what it had not yet sent into the store, and only then is the store closed.
	stopped := make(chan struct{})
	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
		got := <-sig
		log.Printf("Received %v; shutting down", got)
		srv.Close()
		close(stopped)
	}()

	if err := srv.Start(envOr("LISTEN_ADDR", ":8080")); err != nil {
		log.Fatal(err)
	}
	<-stopped
	if err := store.Close(); err != nil {
		log.Printf("[ERROR] closing the store: %v", err)
	}
	log.Printf("Stopped cleanly")
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// writeDevCert creates dir/cert.pem and dir/key.pem. Extra arguments are added
// to the certificate as host names or IP addresses, for reaching the server
// from a phone on the same network.
func writeDevCert(dir string, hosts []string) error {
	certPEM, keyPEM, err := common.GenerateSelfSigned(hosts...)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "cert.pem"), certPEM, 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "key.pem"), keyPEM, 0o600); err != nil {
		return err
	}
	_, fp, err := common.ServerTLSConfig(certPEM, keyPEM)
	if err != nil {
		return err
	}
	fmt.Printf("Wrote %s/cert.pem and %s/key.pem\nFingerprint: %s\nClients pin this fingerprint; compare it when a client first connects.\n",
		dir, dir, common.FormatFingerprint(fp))
	return nil
}
