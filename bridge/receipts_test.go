package bridge

import (
	"core"
	"encoding/json"
	"testing"
	"time"
)

// A real server and several devices, through the bridge: the ticks an outgoing
// message gets as the server takes it, a device has it and a person reads it.

// sent returns the outgoing message with this text, as the app would read it.
func sent(t *testing.T, d *device, conv, text string) message {
	t.Helper()
	s, err := d.e.Messages(accountOf(t, d.e).ID, conv, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	var msgs []message
	if err := json.Unmarshal([]byte(s), &msgs); err != nil {
		t.Fatal(err)
	}
	for _, m := range msgs {
		if m.Outgoing && m.Text == text {
			return m
		}
	}
	return message{}
}

func awaitDelivery(t *testing.T, d *device, conv, text, want string) message {
	t.Helper()
	var m message
	eventually(t, "the message "+text+" to be "+want, func() bool {
		m = sent(t, d, conv, text)
		return m.Delivery == want
	})
	return m
}

// stays checks that a message holds at a delivery state for a while.
func stays(t *testing.T, d *device, conv, text, want string) {
	t.Helper()
	for end := time.Now().Add(700 * time.Millisecond); time.Now().Before(end); time.Sleep(50 * time.Millisecond) {
		if got := sent(t, d, conv, text).Delivery; got != want {
			t.Fatalf("%q is %q, want it to stay %q", text, got, want)
		}
	}
}

func receiptDevices(t *testing.T, names ...string) (*serverProc, []*device) {
	t.Helper()
	saved := core.SetReconnectDelayForTest(50 * time.Millisecond)
	t.Cleanup(func() { core.SetReconnectDelayForTest(saved) })
	srv := startServer(t)
	var out []*device
	for _, n := range names {
		d := newDevice(t, n)
		trustAndRegister(t, d, srv, n)
		out = append(out, d)
	}
	return srv, out
}

func TestAMessageGainsItsTicksOneStepAtATime(t *testing.T) {
	_, ds := receiptDevices(t, "alice", "bob")
	alice, bob := ds[0], ds[1]
	dm := openChat(t, alice.e, "bob")

	// Bob is away, so the server can only say it took the message.
	bob.e.Pause()
	time.Sleep(200 * time.Millisecond)
	if err := alice.e.SendText(dm, "while you were away"); err != nil {
		t.Fatal(err)
	}
	m := awaitDelivery(t, alice, dm, "while you were away", "accepted")
	if m.Total != 1 || m.DeliveredCount != 0 {
		t.Fatalf("message: %+v", m)
	}
	stays(t, alice, dm, "while you were away", "accepted")

	// Bob's device gets it: two plain ticks.
	n := alice.h.count()
	bob.e.SetForeground(true)
	m = awaitDelivery(t, alice, dm, "while you were away", "delivered")
	if m.DeliveredCount != 1 || m.ReadCount != 0 {
		t.Fatalf("message: %+v", m)
	}
	stays(t, alice, dm, "while you were away", "delivered")

	// Bob reads it: two coloured ticks, and the app is told as it happens.
	eventually(t, "the chat on bob's device", func() bool { return len(conversations(t, bob.e)) == 1 })
	if err := bob.e.MarkRead(dm); err != nil {
		t.Fatal(err)
	}
	m = awaitDelivery(t, alice, dm, "while you were away", "read")
	if m.ReadCount != 1 || m.Total != 1 {
		t.Fatalf("message: %+v", m)
	}
	ev := alice.h.waitFor(t, KindMessageStatus, n, func(p map[string]any) bool { return p["delivery"] == "read" })
	if ev["convID"] != dm || ev["readCount"] != float64(1) {
		t.Fatalf("status event: %v", ev)
	}
}

func TestTheChatListShowsHowFarTheLastMessageGot(t *testing.T) {
	_, ds := receiptDevices(t, "alice", "bob")
	alice, bob := ds[0], ds[1]
	dm := openChat(t, alice.e, "bob")
	alice.e.SendText(dm, "hi")
	eventually(t, "the list to show two ticks", func() bool {
		l := chatList(t, alice.e)
		return len(l) == 1 && l[0].PreviewFromMe && l[0].PreviewDelivery == "delivered"
	})
	eventually(t, "the chat on bob's device", func() bool { return len(conversations(t, bob.e)) == 1 })
	bob.e.MarkRead(dm)
	eventually(t, "the list to show coloured ticks", func() bool { return chatList(t, alice.e)[0].PreviewDelivery == "read" })
	// Bob's own list shows no ticks for a message that is not his.
	if l := chatList(t, bob.e); l[0].PreviewFromMe || l[0].PreviewDelivery != "" {
		t.Fatalf("bob's list: %+v", l[0])
	}
}

func TestReceiptsDoNotMakeChatsOrNoise(t *testing.T) {
	_, ds := receiptDevices(t, "alice", "bob")
	alice, bob := ds[0], ds[1]
	dm := openChat(t, alice.e, "bob")
	alice.e.SendText(dm, "hi")
	eventually(t, "the chat on bob's device", func() bool { return len(conversations(t, bob.e)) == 1 })
	bob.e.MarkRead(dm)
	awaitDelivery(t, alice, dm, "hi", "read")

	// One chat each, and the only message either has is the one that was sent.
	for _, d := range ds {
		if cs := conversations(t, d.e); len(cs) != 1 {
			t.Fatalf("%d conversations", len(cs))
		}
	}
	s, _ := bob.e.Messages(accountOf(t, bob.e).ID, dm, 0, 100)
	var msgs []message
	json.Unmarshal([]byte(s), &msgs)
	if len(msgs) != 1 {
		t.Fatalf("bob's history has %d messages: %s", len(msgs), s)
	}
	if l := chatList(t, alice.e); len(l) != 1 || l[0].Unread != 0 {
		t.Fatalf("alice's list: %+v", l)
	}
}

func TestReadReceiptsCanBeTurnedOff(t *testing.T) {
	_, ds := receiptDevices(t, "alice", "bob")
	alice, bob := ds[0], ds[1]
	bob.e.SetSendReadReceipts(false)
	dm := openChat(t, alice.e, "bob")
	alice.e.SendText(dm, "private")
	awaitDelivery(t, alice, dm, "private", "delivered")
	eventually(t, "the chat on bob's device", func() bool { return len(conversations(t, bob.e)) == 1 })
	bob.e.MarkRead(dm)
	stays(t, alice, dm, "private", "delivered")

	// Turning it back on does not report what was read while it was off.
	bob.e.SetSendReadReceipts(true)
	bob.e.MarkRead(dm)
	stays(t, alice, dm, "private", "delivered")
	alice.e.SendText(dm, "later")
	eventually(t, "the second message on bob's device", func() bool {
		return chatList(t, bob.e)[0].Unread == 1
	})
	bob.e.MarkRead(dm)
	awaitDelivery(t, alice, dm, "later", "read")
	if got := sent(t, alice, dm, "private").Delivery; got != "delivered" {
		t.Fatalf("what was read while receipts were off is %q", got)
	}
}

func TestAReadWhileOfflineIsReportedOnReconnecting(t *testing.T) {
	_, ds := receiptDevices(t, "alice", "bob")
	alice, bob := ds[0], ds[1]
	dm := openChat(t, alice.e, "bob")
	alice.e.SendText(dm, "read me offline")
	awaitDelivery(t, alice, dm, "read me offline", "delivered")
	eventually(t, "the chat on bob's device", func() bool { return len(conversations(t, bob.e)) == 1 })

	bob.e.Pause()
	time.Sleep(200 * time.Millisecond)
	if err := bob.e.MarkRead(dm); err != nil {
		t.Fatal(err)
	}
	stays(t, alice, dm, "read me offline", "delivered")
	bob.e.SetForeground(true)
	awaitDelivery(t, alice, dm, "read me offline", "read")
}

func TestAGroupMessageIsReadOnlyWhenEveryoneHasRead(t *testing.T) {
	_, ds := receiptDevices(t, "alice", "bob", "carol")
	alice, bob, carol := ds[0], ds[1], ds[2]
	gid, err := alice.e.CreateGroup("trio", `["bob","carol"]`)
	if err != nil {
		t.Fatal(err)
	}
	if err := alice.e.SendText(gid, "to all"); err != nil {
		t.Fatal(err)
	}
	m := awaitDelivery(t, alice, gid, "to all", "delivered")
	if m.Total != 2 || m.DeliveredCount != 2 {
		t.Fatalf("message: %+v", m)
	}
	eventually(t, "the group on both devices", func() bool {
		return chatList(t, bob.e)[0].Unread == 1 && chatList(t, carol.e)[0].Unread == 1
	})

	bob.e.MarkRead(gid)
	eventually(t, "bob's read to be counted", func() bool { return sent(t, alice, gid, "to all").ReadCount == 1 })
	if m := sent(t, alice, gid, "to all"); m.Delivery != "delivered" || m.Total != 2 {
		t.Fatalf("with one of two read: %+v", m)
	}
	carol.e.MarkRead(gid)
	awaitDelivery(t, alice, gid, "to all", "read")
}

func TestSomeoneWhoLeavesNoLongerHoldsTheTicksBack(t *testing.T) {
	_, ds := receiptDevices(t, "alice", "bob", "carol")
	alice, bob, carol := ds[0], ds[1], ds[2]
	gid, err := alice.e.CreateGroup("trio", `["bob","carol"]`)
	if err != nil {
		t.Fatal(err)
	}
	alice.e.SendText(gid, "before")
	awaitDelivery(t, alice, gid, "before", "delivered")
	eventually(t, "the group on bob's device", func() bool { return chatList(t, bob.e)[0].Unread == 1 })
	bob.e.MarkRead(gid)
	eventually(t, "bob's read", func() bool { return sent(t, alice, gid, "before").ReadCount == 1 })
	stays(t, alice, gid, "before", "delivered")

	// Carol never read it, and now she is gone: everyone who is left has.
	if err := alice.e.GroupAction(gid, "remove", "carol"); err != nil {
		t.Fatal(err)
	}
	m := awaitDelivery(t, alice, gid, "before", "read")
	if m.Total != 1 || m.ReadCount != 1 {
		t.Fatalf("message: %+v", m)
	}
	_ = carol
}
