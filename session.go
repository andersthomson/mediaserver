package main

import (
	"encoding/json"
	"sync"
)

type Sessions struct {
	sync.RWMutex
	m map[string]User
}

func (s *Sessions) ToJson() []byte {
	s.RLock()
	defer s.RUnlock()
	sj, err := json.MarshalIndent(s.m, "", "   ")
	if err != nil {
		return nil
	}
	return sj
}

func (s *Sessions) FromJson(sj []byte) {
	s.Lock()
	defer s.Unlock()
	_ = json.Unmarshal(sj, &s.m)
}
