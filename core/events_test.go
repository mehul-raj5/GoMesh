package core

import (
	"sync"
	"testing"
)

// eventLog collects what the engine tells its host during a test.
type eventLog struct {
	mu     sync.Mutex
	events []Event
}

// captureEvents installs a sink that records every event until the test ends.
func captureEvents(t *testing.T) *eventLog {
	t.Helper()
	l := &eventLog{}
	saved := tcl.sink
	tcl.sink = func(ev Event) {
		l.mu.Lock()
		l.events = append(l.events, ev)
		l.mu.Unlock()
	}
	t.Cleanup(func() { tcl.sink = saved; tcl.leaving.Store(false) })
	return l
}

func (l *eventLog) all() []Event {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]Event(nil), l.events...)
}

func (l *eventLog) has(kind EventKind) bool {
	for _, ev := range l.all() {
		if ev.Kind == kind {
			return true
		}
	}
	return false
}

// worrying returns the notices at warning level or above.
func (l *eventLog) worrying() []Event {
	var out []Event
	for _, ev := range l.all() {
		if ev.Kind == EventNotice && ev.Level >= LevelWarn {
			out = append(out, ev)
		}
	}
	return out
}

func (l *eventLog) reset() {
	l.mu.Lock()
	l.events = nil
	l.mu.Unlock()
}
