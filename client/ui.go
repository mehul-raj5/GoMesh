package main

import (
	"core"
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/progress"
	"github.com/charmbracelet/bubbles/textarea"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type UIState int

const (
	StateMenu UIState = iota
	StateChat
	StateCreateGroup
	StateDirectInit
	StateWait
)

type appModel struct {
	state           UIState
	viewport        viewport.Model
	systemViewport  viewport.Model
	sidebarViewport viewport.Model
	textarea        textarea.Model
	width           int
	height          int
	chatHistory     map[[16]byte][]string
	unreadCounts    map[[16]byte]int
	systemMessages  []string

	fileProgress  progress.Model
	isDownloading bool

	activeConv [16]byte

	suggestions []string
	paramHint   string

	status string // the connection, as the header shows it
}

func initialModel() appModel {
	ta := textarea.New()
	ta.Placeholder = "Type a message..."
	ta.Focus()
	ta.CharLimit = 1000
	ta.SetHeight(3)

	vp := viewport.New(60, 20)
	vp.SetContent("Welcome to ConnHub!\nType /help for commands.")

	vpSys := viewport.New(20, 20)
	vpSys.SetContent("System & Command Logs")

	vpSide := viewport.New(20, 20)
	vpSide.SetContent("Active Chats")

	return appModel{
		state:           StateMenu,
		textarea:        ta,
		viewport:        vp,
		systemViewport:  vpSys,
		sidebarViewport: vpSide,
		chatHistory:     make(map[[16]byte][]string),
		unreadCounts:    make(map[[16]byte]int),
		systemMessages:  []string{},
		fileProgress:    progress.New(progress.WithDefaultGradient()),
		status:          "🟢 Connected as " + cl.Username(),
	}
}

type NetworkMsg struct {
	ConversationID [16]byte
	SenderName     string
	Content        string
	IsFile         bool
	IsSystemMeta   bool
}

type ProgressMsg float64

// quitMsg ends the program; main prints why once the screen is restored.
type quitMsg string

// connMsg is the connection changing state.
type connMsg core.ConnState

func (m appModel) Init() tea.Cmd {
	return textarea.Blink
}

func (m appModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var (
		taCmd     tea.Cmd
		vpCmd     tea.Cmd
		vpSysCmd  tea.Cmd
		vpSideCmd tea.Cmd
	)

	m.textarea, taCmd = m.textarea.Update(msg)
	m.viewport, vpCmd = m.viewport.Update(msg)
	m.systemViewport, vpSysCmd = m.systemViewport.Update(msg)
	m.sidebarViewport, vpSideCmd = m.sidebarViewport.Update(msg)

	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.Type {
		case tea.KeyCtrlC, tea.KeyEsc:
			return m, tea.Quit

		case tea.KeyTab:
			v := m.textarea.Value()
			if strings.HasPrefix(v, "/c") && !strings.HasPrefix(v, "/chat") {
				m.textarea.SetValue("/chat ")
				m.textarea.CursorEnd()
			} else if strings.HasPrefix(v, "/g") && !strings.HasPrefix(v, "/group") {
				m.textarea.SetValue("/group ")
				m.textarea.CursorEnd()
			} else if strings.HasPrefix(v, "/d") && !strings.HasPrefix(v, "/dm") {
				m.textarea.SetValue("/dm ")
				m.textarea.CursorEnd()
			} else if strings.HasPrefix(v, "/a") && !strings.HasPrefix(v, "/add") && !strings.HasPrefix(v, "/adm") {
				m.textarea.SetValue("/add ")
				m.textarea.CursorEnd()
			} else if strings.HasPrefix(v, "/adm") && !strings.HasPrefix(v, "/admin") {
				m.textarea.SetValue("/admin ")
				m.textarea.CursorEnd()
			} else if strings.HasPrefix(v, "/r") && !strings.HasPrefix(v, "/remove") {
				m.textarea.SetValue("/remove ")
				m.textarea.CursorEnd()
			} else if strings.HasPrefix(v, "/remove_a") && !strings.HasPrefix(v, "/remove_admin") {
				m.textarea.SetValue("/remove_admin ")
				m.textarea.CursorEnd()
			} else if strings.HasPrefix(v, "/le") && !strings.HasPrefix(v, "/leave") {
				m.textarea.SetValue("/leave")
				m.textarea.CursorEnd()
			} else if strings.HasPrefix(v, "/f") && !strings.HasPrefix(v, "/file") {
				m.textarea.SetValue("/file ")
				m.textarea.CursorEnd()
			} else if strings.HasPrefix(v, "/h") && !strings.HasPrefix(v, "/help") {
				m.textarea.SetValue("/help")
				m.textarea.CursorEnd()
			} else if strings.HasPrefix(v, "/s") && !strings.HasPrefix(v, "/safety") {
				m.textarea.SetValue("/safety")
			} else if strings.HasPrefix(v, "/lo") && !strings.HasPrefix(v, "/logout") {
				m.textarea.SetValue("/logout")
				m.textarea.CursorEnd()
			} else if strings.HasPrefix(v, "/l") && !strings.HasPrefix(v, "/list") && !strings.HasPrefix(v, "/lo") {
				m.textarea.SetValue("/list")
				m.textarea.CursorEnd()
			}
			return m, nil

		case tea.KeyEnter:
			v := m.textarea.Value()
			v = strings.TrimSpace(v)
			if v != "" {
				if strings.HasPrefix(v, "/") {
					handleSlashCommand(v, &m)
				} else if m.state == StateChat {

					timestamp := time.Now().Format("03:04 PM")
					timePrefix := lipgloss.NewStyle().Foreground(lipgloss.Color("240")).Render(fmt.Sprintf("[%s]", timestamp))
					youPrefix := lipgloss.NewStyle().Foreground(lipgloss.Color("86")).Bold(true).Render("You:")

					formattedLine := fmt.Sprintf("%s %s %s", timePrefix, youPrefix, v)
					m.chatHistory[m.activeConv] = append(m.chatHistory[m.activeConv], formattedLine)
					m.viewport.SetContent(strings.Join(m.chatHistory[m.activeConv], "\n"))

					if m.activeConv != [16]byte{} {
						go sendText(m.activeConv, v)
					} else {
						tuiPrintln("No active conversation selected. Use /chat <id> to select one, or /list to view them.")
					}
				}
				m.textarea.Reset()
				m.viewport.GotoBottom()
			}
			return m, nil
		}

		v := m.textarea.Value()
		m.suggestions = nil
		m.paramHint = ""

		if strings.HasPrefix(v, "/") {
			parts := strings.SplitN(v, " ", 2)
			cmd := parts[0]
			if cmd == "/chat" {
				m.paramHint = "<number>"
				var chats []string
				for i, c := range cl.Conversations() {
					chats = append(chats, fmt.Sprintf("%d: %s", i, c.Name))
					if len(chats) >= 3 {
						break
					}
				}
				m.suggestions = chats
			} else if cmd == "/group" {
				if len(parts) > 1 && strings.Contains(parts[1], " ") {
					m.paramHint = "<user1,user2>"
				} else {
					m.paramHint = "<name> <user1,user2>"
				}
			} else if cmd == "/dm" {
				m.paramHint = "<username>"
			} else if cmd == "/add" || cmd == "/remove" || cmd == "/admin" || cmd == "/remove_admin" {
				m.paramHint = "<username>"
			} else if cmd == "/leave" {
				m.paramHint = ""
			} else if cmd == "/file" {
				m.paramHint = "<path>"
			}
		}

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height

		sideWidth := int(float32(msg.Width) * 0.20)
		chatWidth := int(float32(msg.Width) * 0.55)
		sysWidth := msg.Width - sideWidth - chatWidth - 6

		m.sidebarViewport.Width = sideWidth
		m.sidebarViewport.Height = msg.Height - 7

		m.viewport.Width = chatWidth
		m.viewport.Height = msg.Height - 7

		m.systemViewport.Width = sysWidth
		m.systemViewport.Height = msg.Height - 7

		m.textarea.SetWidth(msg.Width)
		m.fileProgress.Width = sysWidth
		updateSidebar(&m)

	case NetworkMsg:
		if msg.IsSystemMeta {
			formattedMsg := fmt.Sprintf("[SYSTEM]\n%s\n", msg.Content)
			m.systemMessages = append(m.systemMessages, formattedMsg)
			m.systemViewport.SetContent(strings.Join(m.systemMessages, "\n"))
			m.systemViewport.GotoBottom()
		} else {
			timestamp := time.Now().Format("03:04 PM")
			timePrefix := lipgloss.NewStyle().Foreground(lipgloss.Color("240")).Render(fmt.Sprintf("[%s]", timestamp))

			coloredSender := lipgloss.NewStyle().Foreground(lipgloss.Color("205")).Bold(true).Render(msg.SenderName + ":")
			formattedMsg := fmt.Sprintf("%s %s %s", timePrefix, coloredSender, msg.Content)

			m.chatHistory[msg.ConversationID] = append(m.chatHistory[msg.ConversationID], formattedMsg)

			if msg.ConversationID == m.activeConv {
				m.viewport.SetContent(strings.Join(m.chatHistory[m.activeConv], "\n"))
				m.viewport.GotoBottom()
			} else {

				m.unreadCounts[msg.ConversationID]++
				updateSidebar(&m)

				groupName := cl.ConversationName(msg.ConversationID)
				alertMsg := fmt.Sprintf("[SYSTEM]\nNew message from %s in %s\n", msg.SenderName, groupName)
				m.systemMessages = append(m.systemMessages, alertMsg)
				m.systemViewport.SetContent(strings.Join(m.systemMessages, "\n"))
				m.systemViewport.GotoBottom()
			}
		}

	case ProgressMsg:
		var cmd tea.Cmd
		if float64(msg) >= 1.0 {
			m.isDownloading = false
			m.systemMessages = append(m.systemMessages, "[SYSTEM]\nFile transfer complete.")
			m.systemViewport.SetContent(strings.Join(m.systemMessages, "\n"))
			m.systemViewport.GotoBottom()
		} else {
			m.isDownloading = true
		}
		cmd = m.fileProgress.SetPercent(float64(msg))
		return m, tea.Batch(taCmd, vpCmd, vpSysCmd, vpSideCmd, cmd)

	case quitMsg:
		quitReason.Store((*string)(&msg))
		return m, tea.Quit

	case connMsg:
		switch core.ConnState(msg) {
		case core.StateOnline:
			m.status = "🟢 Connected as " + cl.Username()
		case core.StateConnecting:
			m.status = "🟡 Reconnecting…"
		default:
			m.status = "🔴 Offline"
		}

	case progress.FrameMsg:
		progressModel, cmd := m.fileProgress.Update(msg)
		m.fileProgress = progressModel.(progress.Model)
		return m, tea.Batch(taCmd, vpCmd, vpSysCmd, vpSideCmd, cmd)
	}

	return m, tea.Batch(taCmd, vpCmd, vpSysCmd, vpSideCmd)
}

func updateSidebar(m *appModel) {
	var lines []string
	for idx, c := range cl.Conversations() {
		if unread := m.unreadCounts[c.ID]; unread > 0 {
			indicator := lipgloss.NewStyle().Foreground(lipgloss.Color("9")).Render(fmt.Sprintf("[%d]", unread))
			lines = append(lines, fmt.Sprintf("%d: %s %s", idx, indicator, c.Name))
		} else {
			lines = append(lines, fmt.Sprintf("%d: %s", idx, c.Name))
		}
	}

	if len(lines) == 0 {
		m.sidebarViewport.SetContent("No active chats.\nType /list for options.")
	} else {
		m.sidebarViewport.SetContent(strings.Join(lines, "\n"))
	}
}

func (m appModel) View() string {
	statusLine := m.status
	activeName := "None"
	if m.activeConv != [16]byte{} {
		activeName = cl.ConversationName(m.activeConv)
	}

	headerConfig := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("#FAFAFA")).
		Background(lipgloss.Color("#7D56F4")).
		PaddingLeft(1).
		PaddingRight(1).
		MarginBottom(1)

	headerText := fmt.Sprintf(" ConnHub E2EE | %s | Active: %s ", statusLine, activeName)
	header := headerConfig.Render(headerText)

	hintStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
	hintBlock := " "
	if len(m.suggestions) > 0 {
		hintBlock = hintStyle.Render(strings.Join(m.suggestions, " | "))
	} else if m.paramHint != "" {
		hintBlock = hintStyle.Render(m.paramHint)
	}

	sideBox := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("236")).
		Width(m.sidebarViewport.Width).
		Height(m.sidebarViewport.Height).
		Render(m.sidebarViewport.View())

	chatBox := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("62")).
		Width(m.viewport.Width).
		Height(m.viewport.Height).
		Render(m.viewport.View())

	sysContent := m.systemViewport.View()
	if m.isDownloading {
		sysContent += "\n\n" + m.fileProgress.View()
	}

	sysBox := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("240")).
		Width(m.systemViewport.Width).
		Height(m.systemViewport.Height).
		Render(sysContent)

	splitPanes := lipgloss.JoinHorizontal(lipgloss.Top, sideBox, chatBox, sysBox)

	if m.state == StateMenu {
		return lipgloss.JoinVertical(lipgloss.Left,
			header,
			splitPanes,
			hintBlock,
			m.textarea.View(),
		)
	}

	return lipgloss.JoinVertical(lipgloss.Left,
		header,
		splitPanes,
		hintBlock,
		m.textarea.View(),
	)
}

// sendText sends a message from the composer and reports a failure in the
// system pane.
func sendText(convID [16]byte, text string) {
	if err := cl.SendText(convID, text); err != nil {
		tuiPrintf("[ERROR] Could not send: %v", err)
	}
}

func showSafetyNumber(convID [16]byte) {
	if convID == [16]byte{} || cl.IsGroup(convID) {
		tuiPrintln("Usage: /safety (Requires an active private chat)")
		return
	}
	number, err := cl.SafetyNumber(convID)
	if err != nil {
		tuiPrintf("Safety number unavailable: %v", err)
		return
	}
	tuiPrintf("Safety number for %s:\n%s\nRead this to them over a channel you trust. If your two screens differ, someone is in the middle.",
		cl.ConversationName(convID), number)
}

// renderHistory formats the last messages the device kept for a chat.
func renderHistory(convID [16]byte) []string {
	msgs, err := cl.HistoryMessages(cl.UserID(), convID, 0, 200)
	if err != nil {
		tuiPrintf("[ERROR] Could not read this chat's history: %v", err)
		return nil
	}
	var lines []string
	for _, h := range msgs {
		ts := lipgloss.NewStyle().Foreground(lipgloss.Color("240")).Render(fmt.Sprintf("[%s]", h.Time.Format("03:04 PM")))
		who := lipgloss.NewStyle().Foreground(lipgloss.Color("205")).Bold(true).Render(h.SenderName + ":")
		if h.Outgoing {
			who = lipgloss.NewStyle().Foreground(lipgloss.Color("86")).Bold(true).Render("You:")
		}
		text := h.Text
		if h.Media != nil {
			text = fmt.Sprintf("📎 %s (%s)", h.Media.FileName, humanSize(h.Media.Size))
		}
		lines = append(lines, fmt.Sprintf("%s %s %s", ts, who, text))
	}
	return lines
}

// showOtherAccounts lists the chats this device kept for accounts other than
// the one signed in. They can be read, not written to.
func showOtherAccounts() {
	accts, err := cl.HistoryAccounts()
	if err != nil {
		tuiPrintf("[ERROR] %v", err)
		return
	}
	shown := false
	for _, a := range accts {
		if a.ID == cl.UserID() {
			continue
		}
		convs, err := cl.HistoryConversations(a.ID)
		if err != nil {
			tuiPrintf("[ERROR] %s: %v", a.Username, err)
			continue
		}
		shown = true
		tuiPrintf("Previous account %s (read-only):", a.Username)
		for _, c := range convs {
			msgs, _ := cl.HistoryMessages(a.ID, c.ConvID, 0, 1)
			last := ""
			if len(msgs) > 0 {
				last = msgs[0].Text
			}
			tuiPrintf("  %s — %d message(s). Last: %s", c.Name, c.Messages, last)
		}
	}
	if !shown {
		tuiPrintln("No other account has chats kept on this device.")
	}
}

// report shows a command's error, if it had one.
func report(err error) {
	if err != nil {
		tuiPrintf("[ERROR] %v", err)
	}
}

func listConversations() {
	convs := cl.Conversations()
	if len(convs) == 0 {
		tuiPrintln("No conversations yet. Start one with /dm <username> or /group <name> <user1,user2>.")
		return
	}
	for i, c := range convs {
		kind := "Private"
		if c.IsGroup {
			kind = "Group"
		}
		tuiPrintf("%d. %s [%s] (%x)", i, c.Name, kind, c.ID[:4])
	}
}

func tuiPrintf(format string, a ...any) {
	if program != nil {
		go program.Send(NetworkMsg{IsSystemMeta: true, Content: fmt.Sprintf(format, a...)})
	} else {
		fmt.Printf(format, a...)
	}
}

func tuiPrintln(a ...any) {
	if program != nil {
		go program.Send(NetworkMsg{IsSystemMeta: true, Content: fmt.Sprint(a...)})
	} else {
		fmt.Println(a...)
	}
}

func tuiPrint(a ...any) {
	if program != nil {
		go program.Send(NetworkMsg{IsSystemMeta: true, Content: fmt.Sprint(a...)})
	} else {
		fmt.Print(a...)
	}
}

func handleSlashCommand(input string, m *appModel) {
	parts := strings.SplitN(input[1:], " ", 2)
	cmd := parts[0]
	args := ""
	if len(parts) > 1 {
		args = strings.TrimSpace(parts[1])
	}

	switch cmd {
	case "help":
		tuiPrintln("Commands:\n/help - Show this message\n/list - List conversations\n/chat <number> - Switch active chat\n/group <name> <user1,user2> - Create group\n/dm <username> - Start private chat, or start a fresh secure session if one exists\n/add <username> - Add user to current group\n/remove <username> - Remove user from group\n/admin <username> - Make user admin\n/remove_admin <username> - Remove admin\n/leave - Leave current group\n/file <path> - Send file to current chat\n/safety - Show the safety number for the current private chat\n/history - Show chats kept on this device for other accounts (read-only)\n/logout [--delete-history] - Sign out and delete this device's keys, and optionally this account's history")
	case "list":
		listConversations()
	case "chat":
		var idx int
		if _, err := fmt.Sscanf(args, "%d", &idx); err == nil {
			convs := cl.Conversations()
			var convID [16]byte
			var name string
			if idx >= 0 && idx < len(convs) {
				convID, name = convs[idx].ID, convs[idx].Name
			}
			if name != "" {
				m.activeConv = convID
				m.state = StateChat

				m.unreadCounts[convID] = 0
				updateSidebar(m)

				// The device's history is the record; the pane shows its latest part.
				if kept := renderHistory(convID); len(kept) > 0 {
					m.chatHistory[convID] = kept
				}
				history := m.chatHistory[convID]
				if len(history) == 0 {
					m.viewport.SetContent("No messages yet. Say hi!")
				} else {
					m.viewport.SetContent(strings.Join(history, "\n"))
				}
				m.viewport.GotoBottom()
			} else {
				tuiPrintln("Invalid chat index. Use /list to see active chats.")
			}
		}
	case "group":
		argsParts := strings.SplitN(args, " ", 2)
		if len(argsParts) == 2 {
			users := strings.Split(argsParts[1], ",")
			go func(name string, users []string) {
				if _, err := cl.CreateGroup(name, users); err != nil {
					tuiPrintf("[ERROR] Could not create the group: %v", err)
				}
			}(argsParts[0], users)
		} else {
			tuiPrintln("Usage: /group <name> <user1,user2>")
		}
	case "dm":
		if args != "" {
			// /dm on a chat that exists starts it over, as it always has; the app
			// keeps that apart, as a deliberate action in the contact's info.
			for _, c := range cl.Conversations() {
				if !c.IsGroup && strings.EqualFold(c.Name, args) {
					report(cl.RestartChat(c.ID))
					return
				}
			}
			go func(name string) {
				if _, err := cl.OpenChat(name); err != nil {
					tuiPrintf("[ERROR] Could not open a chat with %s: %v", name, err)
				} else {
					tuiPrintf("[INFO] Chat with %s ready.", name)
				}
			}(args)
		} else {
			tuiPrintln("Usage: /dm <username>")
		}
	case "add":
		if m.activeConv != [16]byte{} && args != "" {
			report(cl.AddMember(m.activeConv, args))
		} else {
			tuiPrintln("Usage: /add <username> (Requires active group)")
		}
	case "remove":
		if m.activeConv != [16]byte{} && args != "" {
			report(cl.RemoveMember(m.activeConv, args))
		} else {
			tuiPrintln("Usage: /remove <username> (Requires active group)")
		}
	case "admin":
		if m.activeConv != [16]byte{} && args != "" {
			report(cl.MakeAdmin(m.activeConv, args))
		} else {
			tuiPrintln("Usage: /admin <username> (Requires active group)")
		}
	case "remove_admin":
		if m.activeConv != [16]byte{} && args != "" {
			report(cl.RemoveAdmin(m.activeConv, args))
		} else {
			tuiPrintln("Usage: /remove_admin <username> (Requires active group)")
		}
	case "leave":
		if m.activeConv != [16]byte{} {
			report(cl.LeaveGroup(m.activeConv))
		} else {
			tuiPrintln("Usage: /leave (Requires active group)")
		}
	case "history":
		showOtherAccounts()
	case "safety":
		showSafetyNumber(m.activeConv)
	case "file":
		if m.activeConv != [16]byte{} && args != "" {
			if _, err := cl.SendFile(m.activeConv, args); err != nil {
				tuiPrintf("[ERROR] Could not send %s: %v", args, err)
			} else {
				tuiPrintf("Sending media %s...", args)
			}
		} else {
			tuiPrintln("Usage: /file <path> (Requires active chat)")
		}
	case "logout":
		cl.Logout(args == "--delete-history")
	default:
		tuiPrintf("Unknown command: /%s. Type /help for a list of commands.", cmd)
	}
}
