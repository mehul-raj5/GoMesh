package main

import (
	common "common"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type FileAssembly struct {
	Meta           common.FileMetadata
	ReceivedChunks map[int32]bool
	Data           []byte
}

type ClientManager struct {
	UserID   [common.IDSize]byte
	Username string

	Conversations map[[common.IDSize]byte]ConversationInfo

	Usernames map[[common.IDSize]byte]string

	PendingFiles map[[common.IDSize]byte]*FileAssembly

	PublicKeys      map[[common.IDSize]byte][32]byte
	pendingRequests map[[common.IDSize]byte]chan struct{}
	mu              sync.Mutex
}

type ConversationInfo struct {
	Name    string
	IsGroup bool
	Creator [common.IDSize]byte
	Admins  map[[common.IDSize]byte]struct{}
	Members [][common.IDSize]byte
}

func NewClientManager(userID [common.IDSize]byte, username string) *ClientManager {
	log.Printf("[DEBUG] NewClientManager called with UserID: %x\n", userID)
	return &ClientManager{
		UserID:          userID,
		Username:        username,
		Conversations:   make(map[[common.IDSize]byte]ConversationInfo),
		Usernames:       make(map[[common.IDSize]byte]string),
		PendingFiles:    make(map[[common.IDSize]byte]*FileAssembly),
		PublicKeys:      make(map[[common.IDSize]byte][32]byte),
		pendingRequests: make(map[[common.IDSize]byte]chan struct{}),
	}
}

func (m *ClientManager) RegisterConversation(id [common.IDSize]byte, name string, isGroup bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Conversations[id] = ConversationInfo{
		Name:    name,
		IsGroup: isGroup,
		Admins:  make(map[[common.IDSize]byte]struct{}),
		Members: make([][common.IDSize]byte, 0),
	}
	tuiPrintf("[INFO] Conversation registered: %s", name)
}

func (m *ClientManager) SetGroupAdmin(id [common.IDSize]byte, userID [common.IDSize]byte, isAdmin bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if info, ok := m.Conversations[id]; ok {
		if isAdmin {
			info.Admins[userID] = struct{}{}
		} else {
			delete(info.Admins, userID)
		}
		m.Conversations[id] = info
	}
}

func (m *ClientManager) AddMemberToGroup(groupID, userID [common.IDSize]byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if info, ok := m.Conversations[groupID]; ok {
		exists := false
		for _, id := range info.Members {
			if id == userID {
				exists = true
				break
			}
		}
		if !exists {
			info.Members = append(info.Members, userID)
			m.Conversations[groupID] = info
		}
	}
}

func (m *ClientManager) RemoveMemberFromGroup(groupID, userID [common.IDSize]byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if info, ok := m.Conversations[groupID]; ok {
		for i, id := range info.Members {
			if id == userID {
				info.Members = append(info.Members[:i], info.Members[i+1:]...)
				m.Conversations[groupID] = info
				break
			}
		}
	}
}

func (m *ClientManager) GetGroupMembers(groupID [common.IDSize]byte) [][common.IDSize]byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	var members [][common.IDSize]byte
	if info, ok := m.Conversations[groupID]; ok {
		members = append(members, info.Members...)
	}
	return members
}

func (m *ClientManager) AddUser(id [common.IDSize]byte, name string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Usernames[id] = name
}

func (m *ClientManager) GetUsername(id [common.IDSize]byte) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if name, ok := m.Usernames[id]; ok {
		return name
	}
	return fmt.Sprintf("%x", id[:4])
}

func (m *ClientManager) GetConversationName(id [common.IDSize]byte) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if info, ok := m.Conversations[id]; ok {
		return info.Name
	}
	return fmt.Sprintf("%x", id[:4])
}

func (m *ClientManager) IsGroup(id [common.IDSize]byte) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if info, ok := m.Conversations[id]; ok {
		return info.IsGroup
	}
	return false
}

func (m *ClientManager) IsGroupAdmin(id [common.IDSize]byte) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if info, ok := m.Conversations[id]; ok {
		_, isAdmin := info.Admins[m.UserID]
		return isAdmin
	}
	return false
}

func (m *ClientManager) IsUserAdmin(groupID [common.IDSize]byte, userID [common.IDSize]byte) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if info, ok := m.Conversations[groupID]; ok {
		_, isAdmin := info.Admins[userID]
		return isAdmin
	}
	return false
}

func (m *ClientManager) IsGroupCreator(groupID [common.IDSize]byte, userID [common.IDSize]byte) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if info, ok := m.Conversations[groupID]; ok {
		if len(info.Members) > 0 {
			return info.Members[0] == userID
		}
	}
	return false
}

func (m *ClientManager) HandleFileMeta(msgID [common.IDSize]byte, meta common.FileMetadata) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.PendingFiles[msgID] = &FileAssembly{
		Meta:           meta,
		ReceivedChunks: make(map[int32]bool),
		Data:           make([]byte, meta.FileSize),
	}
	tuiPrintf("[INFO] Receiving file: %s (%d bytes)", meta.FileName, meta.FileSize)
}

func (m *ClientManager) HandleFileChunk(msgID [common.IDSize]byte, chunk common.FileChunk) {
	m.mu.Lock()
	defer m.mu.Unlock()

	assembly, ok := m.PendingFiles[msgID]
	if !ok {
		return
	}

	const StandardChunkSize = 32 * 1024
	offset := int64(chunk.ChunkNo) * StandardChunkSize

	if offset+int64(len(chunk.ChunkData)) > int64(len(assembly.Data)) {
		tuiPrintf("[WARNING] Received file chunk out of bounds. Dropping chunk.")
		return
	}

	copy(assembly.Data[offset:], chunk.ChunkData)
	assembly.ReceivedChunks[chunk.ChunkNo] = true

	if program != nil {
		percent := float64(len(assembly.ReceivedChunks)) / float64(assembly.Meta.TotalChunks)
		go program.Send(ProgressMsg(percent))
	}

	if len(assembly.ReceivedChunks) == int(assembly.Meta.TotalChunks) {
		m.finalizeFile(msgID, assembly)
		delete(m.PendingFiles, msgID)
	}
}

func (m *ClientManager) finalizeFile(msgID [common.IDSize]byte, assembly *FileAssembly) {
	dir := "downloads"
	os.MkdirAll(dir, 0755)
	path := filepath.Join(dir, assembly.Meta.FileName)

	if _, err := os.Stat(path); err == nil {
		path += fmt.Sprintf(".%x", msgID[:4])
	}

	if err := os.WriteFile(path, assembly.Data, 0644); err != nil {
		tuiPrintf("[ERROR] Failed to save file: %v", err)
	} else {
		tuiPrintf("[INFO] File saved: %s", path)
	}
}

func (m *ClientManager) GetPublicKey(userID [common.IDSize]byte, fetchFunc func()) ([32]byte, error) {
	m.mu.Lock()
	if key, ok := m.PublicKeys[userID]; ok {
		m.mu.Unlock()
		return key, nil
	}

	ch, pending := m.pendingRequests[userID]
	if !pending {
		ch = make(chan struct{})
		m.pendingRequests[userID] = ch
		m.mu.Unlock()
		fetchFunc()
		m.mu.Lock()
	}

	m.mu.Unlock()

	select {
	case <-ch:
		m.mu.Lock()
		defer m.mu.Unlock()
		if key, ok := m.PublicKeys[userID]; ok {
			return key, nil
		}
		return [32]byte{}, fmt.Errorf("public key not found after fetch")
	case <-time.After(5 * time.Second):
		m.mu.Lock()
		delete(m.pendingRequests, userID)
		m.mu.Unlock()
		return [32]byte{}, fmt.Errorf("timeout waiting for public key")
	}
}

func (m *ClientManager) UpdatePublicKey(userID [common.IDSize]byte, key [32]byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.PublicKeys[userID] = key

	if ch, ok := m.pendingRequests[userID]; ok {
		close(ch)
		delete(m.pendingRequests, userID)
	}
}
