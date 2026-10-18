package core

import (
	"errors"
	"strings"
	"testing"
)

func hasSystemLine(cl *Client, conv [16]byte, sub string) func() bool {
	return func() bool {
		msgs, _ := cl.HistoryMessages(cl.UserID(), conv, 0, 100)
		for _, m := range msgs {
			if m.System && strings.Contains(m.Text, sub) {
				return true
			}
		}
		return false
	}
}

func memberNamed(ms []Member, name string) *Member {
	for i := range ms {
		if ms[i].Name == name {
			return &ms[i]
		}
	}
	return nil
}

// A group made through the API: its ID comes back once the server has taken
// it, its members are listed from the signed log, and what changes in it is
// written into it.
func TestGroupsThroughTheAPI(t *testing.T) {
	srv := startServerProc(t)
	alice, _ := signedInClient(t, srv.addr, "alice")
	bob, _ := signedInClient(t, srv.addr, "bob")
	carol, _ := signedInClient(t, srv.addr, "carol")

	if _, err := alice.CreateGroup("  ", []string{"bob"}); !errors.Is(err, ErrNoGroupName) {
		t.Fatalf("no name: %v", err)
	}
	if _, err := alice.CreateGroup("team", []string{"bob", "nobody"}); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("an unknown member: %v", err)
	}
	if len(alice.Conversations()) != 0 {
		t.Fatal("a refused group was made anyway")
	}

	gid, err := alice.CreateGroup("team", []string{"Bob", "carol"})
	if err != nil {
		t.Fatal(err)
	}
	if !alice.IsGroup(gid) || alice.ConversationName(gid) != "team" {
		t.Fatal("CreateGroup returned before the group existed")
	}
	ms, err := alice.GroupMembers(gid)
	if err != nil || len(ms) != 3 || !ms[0].IsAdmin || !ms[0].IsMe || ms[0].Name != "alice" {
		t.Fatalf("members: %+v %v", ms, err)
	}
	eventually(t, "bob and carol in the group", func() bool { return bob.IsGroup(gid) && carol.IsGroup(gid) })
	eventually(t, "the create kept as a line", hasSystemLine(bob, gid, "created"))

	if err := alice.SendText(gid, "hello team"); err != nil {
		t.Fatal(err)
	}
	eventually(t, "bob reading the group", keptText(bob, gid, "hello team"))
	eventually(t, "carol reading the group", keptText(carol, gid, "hello team"))
	msgs, _ := bob.HistoryMessages(bob.UserID(), gid, 0, 100)
	var got *HistoryMessage
	for i := range msgs {
		if msgs[i].Text == "hello team" {
			got = &msgs[i]
		}
	}
	if got == nil || got.SenderName != "alice" || got.Status != StatusSent {
		t.Fatalf("bob's copy: %+v", got)
	}

	if err := alice.MakeAdmin(gid, "bob"); err != nil {
		t.Fatal(err)
	}
	eventually(t, "bob an admin, as bob sees it", func() bool {
		ms, _ := bob.GroupMembers(gid)
		m := memberNamed(ms, "bob")
		return m != nil && m.IsAdmin && m.IsMe
	})
	eventually(t, "the promotion kept as a line", hasSystemLine(carol, gid, "now an admin"))

	if err := carol.LeaveGroup(gid); err != nil {
		t.Fatal(err)
	}
	eventually(t, "carol gone, as alice sees it", func() bool {
		ms, _ := alice.GroupMembers(gid)
		return len(ms) == 2 && memberNamed(ms, "carol") == nil
	})
	eventually(t, "carol's copy kept, read-only", func() bool {
		list, _ := carol.ChatList()
		return len(list) == 1 && list[0].ID == gid && list[0].ReadOnly
	})
	if !hasSystemLine(carol, gid, "no longer a member")() {
		t.Fatal("carol was not told she left")
	}
}

func systemLines(cl *Client, conv [16]byte, sub string) int {
	msgs, _ := cl.HistoryMessages(cl.UserID(), conv, 0, 100)
	n := 0
	for _, m := range msgs {
		if m.System && strings.Contains(m.Text, sub) {
			n++
		}
	}
	return n
}

// A device that signs in catches up on its groups' logs, but only what
// happened once it held the account's keys is news: the group's history from
// before is not written into the chat again.
func TestAMovedDeviceIsNotToldOldGroupNews(t *testing.T) {
	srv := startServerProc(t)
	alice, _ := signedInClient(t, srv.addr, "alice")
	bob, bobRec := signedInClient(t, srv.addr, "bob")
	carol, _ := signedInClient(t, srv.addr, "carol")
	gid, err := alice.CreateGroup("team", []string{"bob", "carol"})
	if err != nil {
		t.Fatal(err)
	}
	if err := alice.MakeAdmin(gid, "carol"); err != nil {
		t.Fatal(err)
	}
	eventually(t, "bob told of the promotion", hasSystemLine(bob, gid, "now an admin"))

	serverPinsMu.Lock()
	pin := serverPins[srv.addr]
	serverPinsMu.Unlock()
	signIn := func(dir string) *Client {
		t.Helper()
		cl, err := New(Config{DataDir: dir})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(cl.Close)
		if err := cl.CheckServer(srv.addr, func(fp string) bool { return fp == pin }); err != nil {
			t.Fatal(err)
		}
		if err := cl.Login(srv.addr, "bob", testPassword); err != nil {
			t.Fatal(err)
		}
		return cl
	}

	// To a new device, and back to the first one, which kept its history.
	n := bobRec.count()
	moved := signIn(t.TempDir())
	bobRec.waitFor(t, "the first device signed out", n, func(ev Event) bool { return ev.Kind == EventSignedOut })
	eventually(t, "the new device holding bob's keys", hasSystemLine(moved, gid, "now holds your keys"))
	if err := moved.SendText(gid, "from the new device"); err != nil {
		t.Fatal(err)
	}
	eventually(t, "carol reading the new device", keptText(carol, gid, "from the new device"))

	dir := bob.dataDir
	bob.Close()
	back := signIn(dir)
	eventually(t, "the first device holding bob's keys again", func() bool {
		return systemLines(back, gid, "now holds your keys") == 1
	})
	if err := back.SendText(gid, "back on the first device"); err != nil {
		t.Fatal(err)
	}
	eventually(t, "carol reading it", keptText(carol, gid, "back on the first device"))

	for _, c := range []struct {
		who     string
		cl      *Client
		created int
		admin   int
	}{{"the new device", moved, 0, 0}, {"the first device", back, 1, 1}} {
		if got := systemLines(c.cl, gid, "created"); got != c.created {
			t.Errorf("%s: %d \"created\" lines, want %d", c.who, got, c.created)
		}
		if got := systemLines(c.cl, gid, "now an admin"); got != c.admin {
			t.Errorf("%s: %d \"now an admin\" lines, want %d", c.who, got, c.admin)
		}
		if got := systemLines(c.cl, gid, "now holds your keys"); got != 1 {
			t.Errorf("%s: %d \"now holds your keys\" lines, want 1", c.who, got)
		}
	}
}
