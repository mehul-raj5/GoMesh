package core

import (
	common "common"
	"fmt"
	"time"
)

// The engine never prints, never exits and knows nothing about screens: it runs
// inside the terminal client and inside the iOS and macOS apps alike. Everything
// meant for the person using it leaves as an Event, and the host decides how to
// show it.

// Level ranks a notice.
type Level int

const (
	LevelInfo Level = iota
	LevelWarn
	LevelError
)

func (l Level) String() string {
	switch l {
	case LevelWarn:
		return "WARN"
	case LevelError:
		return "ERROR"
	default:
		return "INFO"
	}
}

// EventKind says what an Event reports.
type EventKind int

const (
	// EventNotice is something to tell the user: Text, at Level.
	EventNotice EventKind = iota
	// EventMessage is a message in ConvID from Sender. Media is set for a file.
	EventMessage
	// EventProgress is file transfer Transfer, of the file Text in ConvID,
	// being Progress (0 to 1) done; 1 is finished, and -1 failed. Sender is set
	// for a file being received.
	EventProgress
	// EventConnection is the connection changing to State.
	EventConnection
	// EventSignedOut means this device is no longer the account's: it was
	// replaced, its session ended, or the user signed out. Text says which. The
	// device's keys have been deleted by the time it is sent.
	EventSignedOut
	// EventPasswordRequired means the saved session cannot be resumed with this
	// device's keys, and the host should ask for the password.
	EventPasswordRequired
	// EventMediaSaved is a file Text in ConvID, received and kept sealed on this
	// device as MediaID. ExportMedia writes a copy out.
	EventMediaSaved
	// EventMessageStatus is the kept message Seq in ConvID changing to Status:
	// a queued group message going out, or failing to.
	EventMessageStatus
)

// ConnState is the state of the connection to the server.
type ConnState int

const (
	StateOffline ConnState = iota
	StateConnecting
	StateOnline
)

func (s ConnState) String() string {
	switch s {
	case StateConnecting:
		return "connecting"
	case StateOnline:
		return "online"
	default:
		return "offline"
	}
}

// Event is one thing the engine tells its host.
type Event struct {
	Kind       EventKind
	Level      Level
	Text       string
	ConvID     [16]byte
	Sender     [16]byte
	SenderName string
	Time       time.Time
	Media      *common.MediaMetadata
	Progress   float64
	State      ConnState
	MediaID    string
	Seq        int64
	Status     MessageStatus
	Transfer   string
	// For an EventMessageStatus: how far the message has got, and how many of
	// its Total recipients have it and have read it.
	Delivery       Delivery
	DeliveredCount int
	ReadCount      int
	Total          int
}

func (cl *Client) emit(ev Event) {
	if cl.sink != nil {
		cl.sink(ev)
	}
}

func (cl *Client) notify(level Level, format string, args ...any) {
	cl.emit(Event{Kind: EventNotice, Level: level, Text: fmt.Sprintf(format, args...)})
}

// systemLine tells the host something about one chat, such as a safety number
// changing, and keeps it in that chat's history so it is still there on the
// next start. The event carries the chat's ID.
func (cl *Client) systemLine(convID [16]byte, level Level, format string, args ...any) {
	text := fmt.Sprintf(format, args...)
	if cl.mgr.HasConversation(convID) {
		cl.record(convID, HistoryMessage{System: true, Time: time.Now(), Text: text})
	}
	cl.emit(Event{Kind: EventNotice, Level: level, Text: text, ConvID: convID})
}
