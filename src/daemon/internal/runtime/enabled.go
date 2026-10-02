package runtime

import (
	"sync"
)

type jailEnabledSource struct {
	mu     sync.RWMutex
	states map[string]bool
}

func NewJailEnabledSource() JailEnabledSource {
	return &jailEnabledSource{
		states: make(map[string]bool),
	}
}

func (s *jailEnabledSource) EnabledStates() map[string]bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make(map[string]bool, len(s.states))
	for k, v := range s.states {
		result[k] = v
	}
	return result
}

func (s *jailEnabledSource) SetEnabled(jail string, enabled bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.states[jail] = enabled
}
