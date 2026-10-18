package bridge

import (
	"core"
	"sync"
)

// The event kinds an EventHandler hears.
const (
	KindNotice           = "notice"
	KindMessage          = "message"
	KindProgress         = "progress"
	KindConnection       = "connection"
	KindSignedOut        = "signedOut"
	KindPasswordRequired = "passwordRequired"
	KindMediaSaved       = "mediaSaved"
	KindMessageStatus    = "messageStatus"
)

type eventPayload struct {
	Level      string   `json:"level,omitempty"`
	Text       string   `json:"text,omitempty"`
	ConvID     string   `json:"convID,omitempty"`
	Sender     string   `json:"sender,omitempty"`
	SenderName string   `json:"senderName,omitempty"`
	Time       int64    `json:"time,omitempty"`
	Media      *media   `json:"media,omitempty"`
	Progress   *float64 `json:"progress,omitempty"`
	State      string   `json:"state,omitempty"`
	MediaID    string   `json:"mediaID,omitempty"`
	Seq        int64    `json:"seq,omitempty"`
	Status     string   `json:"status,omitempty"`
	Transfer   string   `json:"transfer,omitempty"`

	Delivery       string `json:"delivery,omitempty"`
	DeliveredCount int    `json:"deliveredCount,omitempty"`
	ReadCount      int    `json:"readCount,omitempty"`
	Total          int    `json:"total,omitempty"`
}

func encodeEvent(ev core.Event) (string, string) {
	p := eventPayload{Text: ev.Text, SenderName: ev.SenderName, Time: millis(ev.Time), MediaID: ev.MediaID, Transfer: ev.Transfer}
	if ev.ConvID != ([16]byte{}) {
		p.ConvID = hexID(ev.ConvID)
	}
	if ev.Sender != ([16]byte{}) {
		p.Sender = hexID(ev.Sender)
	}
	if ev.Media != nil {
		p.Media = &media{FileName: ev.Media.FileName, FileType: ev.Media.FileType, Size: ev.Media.FileSize}
	}
	var kind string
	switch ev.Kind {
	case core.EventNotice:
		kind = KindNotice
		p.Level = map[core.Level]string{core.LevelInfo: "info", core.LevelWarn: "warn", core.LevelError: "error"}[ev.Level]
	case core.EventMessage:
		kind = KindMessage
	case core.EventProgress:
		kind = KindProgress
		progress := ev.Progress
		p.Progress = &progress
	case core.EventConnection:
		kind = KindConnection
		p.State = ev.State.String()
	case core.EventSignedOut:
		kind = KindSignedOut
	case core.EventPasswordRequired:
		kind = KindPasswordRequired
	case core.EventMediaSaved:
		kind = KindMediaSaved
	case core.EventMessageStatus:
		kind = KindMessageStatus
		p.Seq, p.Status = ev.Seq, ev.Status.String()
		p.Delivery, p.DeliveredCount, p.ReadCount, p.Total = ev.Delivery.String(), ev.DeliveredCount, ev.ReadCount, ev.Total
	default:
		kind = KindNotice
	}
	return kind, mustJSON(p)
}

// eventQueue hands events to the app in order, from one goroutine of its own,
// so a slow handler never holds up the engine.
type eventQueue struct {
	mu     sync.Mutex
	cond   *sync.Cond
	items  [][2]string
	closed bool
	h      EventHandler
	done   chan struct{}
}

func newEventQueue(h EventHandler) *eventQueue {
	q := &eventQueue{h: h, done: make(chan struct{})}
	q.cond = sync.NewCond(&q.mu)
	go q.run()
	return q
}

func (q *eventQueue) push(kind, payload string) {
	q.mu.Lock()
	if !q.closed {
		q.items = append(q.items, [2]string{kind, payload})
		q.cond.Signal()
	}
	q.mu.Unlock()
}

// close lets the queue deliver what it holds, then stop.
func (q *eventQueue) close() {
	q.mu.Lock()
	q.closed = true
	q.cond.Signal()
	q.mu.Unlock()
}

func (q *eventQueue) run() {
	defer close(q.done)
	for {
		q.mu.Lock()
		for len(q.items) == 0 && !q.closed {
			q.cond.Wait()
		}
		if len(q.items) == 0 {
			q.mu.Unlock()
			return
		}
		ev := q.items[0]
		q.items[0] = [2]string{}
		q.items = q.items[1:]
		q.mu.Unlock()
		q.h.OnEvent(ev[0], ev[1])
	}
}
