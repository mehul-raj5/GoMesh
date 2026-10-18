package core

import (
	common "common"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// Client is one device's engine: its keys, sessions, groups, connection and
// everything waiting on them. Each signed-in account gets its own Client.
type Client struct {
	// dataDir is where this device keeps its files: its keys, its saved sessions,
	// its session token and the servers it trusts. One data directory is one
	// device. Tests point it at a temporary directory, so wiping a device can never
	// reach the files in the working tree.
	dataDir string
	// leaving is set once this device is signing out. readLoop checks it so the
	// server hanging up is not mistaken for a lost connection. It is read and
	// written on different goroutines, hence the atomic.
	leaving       atomic.Bool
	mgr           *ClientManager
	idMgr         *IdentityManager
	stateStore    *StateStore
	sessionMgr    *SessionManager
	conn          net.Conn
	connLock      sync.Mutex
	dmMu          sync.Mutex
	dmRequests    map[string]struct{}
	convInfoMu    sync.Mutex
	convInfoAsked map[[16]byte]time.Time
	resets        struct {
		mu       sync.Mutex
		sent     map[[16]byte]time.Time
		honoured map[[16]byte]time.Time
	}
	// hist is this device's history file; myHistory is the signed-in account's
	// view of it.
	hist      *history
	myHistory *accountHistory
	// isOnline is set while the client is connected and signed in; stop is
	// closed by Close, ending the reconnect loop; stopOnce guards that.
	isOnline atomic.Bool
	stop     chan struct{}
	stopOnce sync.Once
	// loops counts the read and reconnect loops, so Close can wait for them;
	// wake cuts a reconnect delay short.
	loops sync.WaitGroup
	wake  chan struct{}
	// paused is set by Pause and cleared by ReconnectNow; acks is the current
	// connection's acknowledger.
	paused atomic.Bool
	acks   atomic.Pointer[acker]
	// backoffMin and backoffMax bound the reconnect delay, copied from the
	// package defaults when the client is made.
	backoffMin, backoffMax time.Duration
	// vault holds the account key, the identity keys and the session token.
	vault Vault
	// deviceName is how the server lists this device; empty means the host name.
	deviceName string
	// sink receives every event. Nil means nobody is listening.
	sink    func(Event)
	lookups struct {
		mu      sync.Mutex
		waiting map[[16]byte]chan *common.UserLookup
	}
	intents struct {
		mu sync.Mutex
		m  map[[16]byte]*groupIntent
	}
	unsettledMu     sync.Mutex
	unsettledWarned map[[32]byte]bool
	logMu           sync.Mutex
	logAsked        map[[16]byte]time.Time
	// receipts holds what arrived about a message before the history had it,
	// and readMu keeps two reports of what has been read from interleaving.
	// noReadReceipts, set by the host, keeps this device from telling anyone
	// what it has read.
	receipts       receiptState
	readMu         sync.Mutex
	noReadReceipts atomic.Bool
	// groupOutbox holds messages for a group whose members could not all be reached
	// yet. Sending one anyway would leave the unreachable members unable to read it.
	groupOutbox struct {
		mu sync.Mutex
		m  map[[16]byte][]outboxItem
	}
	// opening holds a caller of OpenChat waiting for the server's answer, by
	// conversation.
	opening struct {
		mu sync.Mutex
		m  map[[16]byte]chan error
	}
	// pending is the client's single queue, sized and swept by the constants above.
	pending *pendingQueue
}

// newClient returns a Client with its fields initialized.
func newClient() *Client {
	cl := &Client{}
	cl.dataDir = "."
	cl.dmRequests = map[string]struct{}{}
	cl.convInfoAsked = map[[16]byte]time.Time{}
	cl.resets = struct {
		mu       sync.Mutex
		sent     map[[16]byte]time.Time
		honoured map[[16]byte]time.Time
	}{sent: map[[16]byte]time.Time{}, honoured: map[[16]byte]time.Time{}}
	cl.lookups = struct {
		mu      sync.Mutex
		waiting map[[16]byte]chan *common.UserLookup
	}{
		waiting: make(map[[16]byte]chan *common.UserLookup),
	}
	cl.intents = struct {
		mu sync.Mutex
		m  map[[16]byte]*groupIntent
	}{m: make(map[[16]byte]*groupIntent)}
	cl.unsettledWarned = map[[32]byte]bool{}
	cl.logAsked = map[[16]byte]time.Time{}
	cl.groupOutbox = struct {
		mu sync.Mutex
		m  map[[16]byte][]outboxItem
	}{m: make(map[[16]byte][]outboxItem)}
	cl.opening.m = map[[16]byte]chan error{}
	cl.pending = newPendingQueue()
	cl.stop = make(chan struct{})
	cl.wake = make(chan struct{}, 1)
	cl.backoffMin, cl.backoffMax = reconnectMin, reconnectMax
	return cl
}
