package core

import (
	"errors"
	"sync"
)

// memVault is a vault in memory. failGet, when set, is what every Get returns:
// a vault that cannot be read right now, as the Keychain is before first unlock.
type memVault struct {
	mu      sync.Mutex
	m       map[string][]byte
	failGet error
	puts    int
}

func newMemVault() *memVault { return &memVault{m: map[string][]byte{}} }

func (v *memVault) Get(name string) ([]byte, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.failGet != nil {
		return nil, v.failGet
	}
	b, ok := v.m[name]
	if !ok {
		return nil, ErrNotInVault
	}
	return append([]byte(nil), b...), nil
}

func (v *memVault) Put(name string, value []byte) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.m[name] = append([]byte(nil), value...)
	v.puts++
	return nil
}

func (v *memVault) Delete(name string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	delete(v.m, name)
	return nil
}

var errLocked = errors.New("the vault is locked until the device is unlocked")
