package main

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
)

// argonParams are the argon2id cost settings. Each hash costs memoryKiB of RAM
// for about a quarter of a second at the defaults, which is why hashing is
// gated: attempts are throttled first, and only a few hashes run at once.
type argonParams struct {
	Time      uint32
	MemoryKiB uint32
	Threads   uint8
}

var defaultArgon = argonParams{Time: 2, MemoryKiB: 64 * 1024, Threads: 2}

const (
	argonSaltLen = 16
	argonKeyLen  = 32
)

// hashPassword returns an argon2id hash in the PHC string format, which carries
// its own parameters so they can be raised later without breaking old hashes.
func hashPassword(password string, p argonParams) (string, error) {
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(password), salt, p.Time, p.MemoryKiB, p.Threads, argonKeyLen)
	b64 := base64.RawStdEncoding
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, p.MemoryKiB, p.Time, p.Threads, b64.EncodeToString(salt), b64.EncodeToString(key)), nil
}

// verifyPassword checks password against a PHC string, in constant time.
func verifyPassword(password, encoded string) (bool, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false, errors.New("not an argon2id hash")
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return false, errors.New("unsupported argon2 version")
	}
	var p argonParams
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &p.MemoryKiB, &p.Time, &p.Threads); err != nil {
		return false, fmt.Errorf("bad argon2 parameters: %w", err)
	}
	b64 := base64.RawStdEncoding
	salt, err := b64.DecodeString(parts[4])
	if err != nil {
		return false, err
	}
	want, err := b64.DecodeString(parts[5])
	if err != nil {
		return false, err
	}
	got := argon2.IDKey([]byte(password), salt, p.Time, p.MemoryKiB, p.Threads, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

// authConfig holds the knobs tests turn down. Production uses defaultAuth.
type authConfig struct {
	Argon argonParams

	// Every register or password login from one IP counts against IPAttempts
	// per IPWindow; resumes, which never hash, get resumeAllowance times that. Failed passwords for one username count against UserFailures
	// per UserWindow. Both are checked before any hashing happens.
	IPAttempts   int
	IPWindow     time.Duration
	UserFailures int
	UserWindow   time.Duration

	// HashSlots is how many password hashes may run at once; HashWait is how
	// long an attempt queues for a slot before it is told to retry later.
	HashSlots int
	HashWait  time.Duration
}

var defaultAuth = authConfig{
	Argon:        defaultArgon,
	IPAttempts:   30,
	IPWindow:     time.Minute,
	UserFailures: 10,
	UserWindow:   15 * time.Minute,
	HashSlots:    4,
	HashWait:     10 * time.Second,
}

var errBusy = errors.New("too many password checks in progress")

type authenticator struct {
	cfg    authConfig
	slots  chan struct{}
	ip     *slidingLimiter
	resume *slidingLimiter
	user   *slidingLimiter
}

// resumeAllowance is how many times IPAttempts an IP may resume per IPWindow.
const resumeAllowance = 10

func newAuthenticator(cfg authConfig) *authenticator {
	return &authenticator{
		cfg:    cfg,
		slots:  make(chan struct{}, cfg.HashSlots),
		ip:     newSlidingLimiter(cfg.IPAttempts, cfg.IPWindow),
		resume: newSlidingLimiter(cfg.IPAttempts*resumeAllowance, cfg.IPWindow),
		user:   newSlidingLimiter(cfg.UserFailures, cfg.UserWindow),
	}
}

// allowIP records a register or password login from ip and reports whether it
// is within the limit.
func (a *authenticator) allowIP(ip string) bool { return a.ip.hit(ip, time.Now()) }

// allowResume records a resume from ip and reports whether it is within the limit.
func (a *authenticator) allowResume(ip string) bool { return a.resume.hit(ip, time.Now()) }

// userLocked reports whether username has had too many recent failures.
func (a *authenticator) userLocked(username string) bool { return a.user.full(username, time.Now()) }

func (a *authenticator) failed(username string)    { a.user.hit(username, time.Now()) }
func (a *authenticator) succeeded(username string) { a.user.reset(username) }

// withSlot runs fn while holding one of the hash slots.
func (a *authenticator) withSlot(fn func()) error {
	select {
	case a.slots <- struct{}{}:
	case <-time.After(a.cfg.HashWait):
		return errBusy
	}
	defer func() { <-a.slots }()
	fn()
	return nil
}

func (a *authenticator) hash(password string) (string, error) {
	var out string
	var herr error
	if err := a.withSlot(func() { out, herr = hashPassword(password, a.cfg.Argon) }); err != nil {
		return "", err
	}
	return out, herr
}

func (a *authenticator) verify(password, encoded string) (bool, error) {
	var ok bool
	var verr error
	if err := a.withSlot(func() { ok, verr = verifyPassword(password, encoded) }); err != nil {
		return false, err
	}
	return ok, verr
}

// slidingLimiter counts events per key over a sliding window.
type slidingLimiter struct {
	mu     sync.Mutex
	max    int
	window time.Duration
	events map[string][]time.Time
}

// limiterSweepAt is how many keys the limiter holds before it sweeps out the
// ones with nothing left in their window, so a flood of distinct keys cannot
// grow it without bound.
const limiterSweepAt = 10000

func newSlidingLimiter(max int, window time.Duration) *slidingLimiter {
	return &slidingLimiter{max: max, window: window, events: map[string][]time.Time{}}
}

func (l *slidingLimiter) recent(key string, now time.Time) []time.Time {
	ev := l.events[key]
	i := 0
	for i < len(ev) && now.Sub(ev[i]) >= l.window {
		i++
	}
	ev = ev[i:]
	if len(ev) == 0 {
		delete(l.events, key)
		return nil
	}
	l.events[key] = ev
	return ev
}

// hit records an event and reports whether key is still within its limit,
// counting this event.
func (l *slidingLimiter) hit(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.events) >= limiterSweepAt {
		for k := range l.events {
			l.recent(k, now)
		}
	}
	ev := l.recent(key, now)
	if len(ev) >= l.max {
		return false
	}
	l.events[key] = append(ev, now)
	return true
}

// full reports whether key has used its limit, without recording anything.
func (l *slidingLimiter) full(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.recent(key, now)) >= l.max
}

func (l *slidingLimiter) reset(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.events, key)
}
