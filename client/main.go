package main

import (
	"bufio"
	common "common"
	"core"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"sync/atomic"

	tea "github.com/charmbracelet/bubbletea"
	"golang.org/x/term"
)

// The terminal client: a thin screen over the engine in core. It asks for the
// server and the password, shows what the engine reports, and passes commands
// on. This directory is the device.

var (
	reader  *bufio.Reader
	cl      *core.Client
	program *tea.Program

	// events carries what the engine reports to the screen. The engine starts
	// before the screen does, so they wait here until it is up.
	events = make(chan core.Event, 1024)

	// quitReason is what main prints once the screen has been given back.
	quitReason atomic.Pointer[string]
)

func main() {
	f, err := os.OpenFile("client.log", os.O_RDWR|os.O_CREATE|os.O_APPEND, 0600)
	if err != nil {
		fmt.Printf("Error opening client.log: %v\n", err)
	} else {
		log.SetOutput(f)
		defer f.Close()
	}
	reader = bufio.NewReader(os.Stdin)

	host, _ := os.Hostname()
	cl, err = core.New(core.Config{
		DataDir:    ".",
		DeviceName: strings.TrimSuffix(host, ".local") + " (terminal)",
		OnEvent:    onEvent,
	})
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	server, _, saved := cl.SavedSession()
	def := "localhost:8080"
	if env := strings.TrimSpace(os.Getenv("GOMESH_SERVER")); env != "" {
		def = env // e.g. the EC2 server, host:port
	}
	if saved && server != "" {
		def = server
	}
	addr := promptLine(fmt.Sprintf("Server address (default %s): ", def))
	if addr == "" {
		addr = def
	}
	// Settle trust in the server before anyone types a password to it.
	if err := cl.CheckServer(addr, confirmFingerprint); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	if err := signIn(addr, saved && server == addr); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	p := tea.NewProgram(initialModel(), tea.WithAltScreen())
	program = p
	go forwardEvents()
	if _, err := p.Run(); err != nil {
		log.Fatalf("Error running program: %v", err)
	}
	cl.Close()
	if r := quitReason.Load(); r != nil {
		fmt.Println(*r)
	}
}

// onEvent is the engine's sink. It never blocks the engine: if the screen has
// fallen far behind, the event is dropped and logged.
func onEvent(ev core.Event) {
	select {
	case events <- ev:
	default:
		log.Printf("[WARN] screen behind; dropped an event of kind %d", ev.Kind) // never its text
	}
}

// forwardEvents turns engine events into screen messages.
func forwardEvents() {
	for ev := range events {
		switch ev.Kind {
		case core.EventNotice:
			program.Send(NetworkMsg{IsSystemMeta: true, Content: fmt.Sprintf("[%s] %s", ev.Level, ev.Text)})
		case core.EventMessage:
			if ev.Media != nil {
				program.Send(mediaMessage(ev.ConvID, ev.SenderName, *ev.Media))
				continue
			}
			program.Send(NetworkMsg{ConversationID: ev.ConvID, SenderName: ev.SenderName, Content: ev.Text})
		case core.EventProgress:
			if ev.Progress >= 0 { // -1 is a failed transfer, reported as a notice too
				program.Send(ProgressMsg(ev.Progress))
			}
		case core.EventMediaSaved:
			// The engine keeps files sealed. The terminal client, a development
			// tool, writes a copy to downloads/ as it always has.
			path, err := cl.ExportMedia(cl.UserID(), ev.MediaID, ev.Text, "downloads")
			if err != nil {
				program.Send(NetworkMsg{IsSystemMeta: true, Content: fmt.Sprintf("[ERROR] Could not save %s: %v", ev.Text, err)})
				continue
			}
			program.Send(NetworkMsg{IsSystemMeta: true, Content: fmt.Sprintf("[INFO] ✓ %s saved to %s", ev.Text, path)})
		case core.EventConnection:
			program.Send(connMsg(ev.State))
			if ev.Text != "" {
				program.Send(NetworkMsg{IsSystemMeta: true, Content: "[INFO] " + ev.Text})
			}
		case core.EventSignedOut:
			program.Send(quitMsg(ev.Text))
		case core.EventPasswordRequired:
			program.Send(quitMsg("This device needs your password again. Run the client to sign in."))
		}
	}
}

func promptLine(prompt string) string {
	fmt.Print(prompt)
	line, _ := reader.ReadString('\n')
	return strings.TrimSpace(line)
}

// readPassword reads a password without echoing it. Piped input, which has no
// terminal to hide, is read as a plain line.
func readPassword(prompt string) string {
	fmt.Print(prompt)
	if fd := int(os.Stdin.Fd()); term.IsTerminal(fd) {
		b, err := term.ReadPassword(fd)
		fmt.Println()
		if err == nil {
			return string(b)
		}
	}
	line, _ := reader.ReadString('\n')
	return strings.TrimRight(line, "\r\n")
}

func confirmFingerprint(fp string) bool {
	fmt.Printf("\nFirst connection to this server. Its certificate fingerprint is:\n\n    %s\n\n"+
		"Compare it with the fingerprint the server printed when it started.\n", common.FormatFingerprint(fp))
	return strings.HasPrefix(strings.ToLower(promptLine("Trust this server? [y/N]: ")), "y")
}

func errorCode(err error) common.ErrorCode {
	var se *common.ServerError
	if errors.As(err, &se) {
		return se.Code
	}
	return common.ErrUnknown
}

// signIn resumes the saved session for addr if there is one, and otherwise asks
// for a username and password.
func signIn(addr string, haveSaved bool) error {
	if haveSaved {
		err := cl.Resume()
		if err == nil {
			fmt.Printf("Signed in as %s.\n", cl.Username())
			return nil
		}
		switch errorCode(err) {
		case common.ErrDeviceReplaced:
			fmt.Println("This account signed in on another device, so this device's keys have been deleted.")
		case common.ErrSessionRevoked:
			fmt.Println("Your session has ended, so this device's keys have been deleted.")
		case common.ErrPasswordRequired:
			fmt.Println("This device's keys changed since you last signed in. Sign in with your password.")
		default:
			return fmt.Errorf("could not resume your session: %w", err)
		}
	}
	return passwordSignIn(addr)
}

func passwordSignIn(addr string) error {
	for attempt := 0; attempt < 5; attempt++ {
		choice := strings.ToLower(promptLine("[l]og in or [r]egister? "))
		register := strings.HasPrefix(choice, "r")
		if !register && !strings.HasPrefix(choice, "l") {
			continue
		}
		username, err := common.NormalizeUsername(promptLine("Username: "))
		if err != nil {
			fmt.Println(err)
			continue
		}
		password := readPassword("Password: ")
		if register {
			if err := common.CheckPassword(password, username); err != nil {
				fmt.Println(err)
				continue
			}
			if readPassword("Confirm password: ") != password {
				fmt.Println("The passwords do not match.")
				continue
			}
			err = cl.Register(addr, username, password)
		} else {
			fmt.Println("If this account is signed in on another device, that device will be signed out.")
			err = cl.Login(addr, username, password)
		}
		if err != nil {
			if errorCode(err) == common.ErrUnknown {
				return err
			}
			fmt.Printf("Refused: %v\n", err)
			continue
		}
		fmt.Printf("Signed in as %s.\n", username)
		return nil
	}
	return errors.New("too many attempts")
}
