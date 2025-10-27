package main

import (
	"encoding/json"
	"sync"
	"time"
)

type SessionEntry struct {
	User     User
	LastUsed time.Time
}
type Sessions struct {
	sync.RWMutex
	m map[string]SessionEntry
}

func (s *Sessions) Add(sessionID string, u User) {
	se := SessionEntry{
		User:     u,
		LastUsed: time.Now(),
	}
	s.Lock()
	s.m[sessionID] = se
	s.Unlock()
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
	type itemT struct {
		IDProvider_ string
	}
	type T map[string]json.RawMessage
	var t T
	err := json.Unmarshal(sj, &t)
	if err != nil {
		panic(err)
	}
	s.Lock()
	defer s.Unlock()
	for k, v := range t {
		type entryTT struct {
			LastUsed time.Time
			User     json.RawMessage
		}
		var entry entryTT
		if err = json.Unmarshal(v, &entry); err != nil {
			panic(err)
		}

		var i itemT
		if err = json.Unmarshal(entry.User, &i); err != nil {
			panic(err)
		}
		switch i.IDProvider_ {
		case "googleIDP":
			var g GoogleUser
			if err = json.Unmarshal(entry.User, &g); err != nil {
				panic(err)
			}
			s.m[k] = SessionEntry{
				User:     g,
				LastUsed: entry.LastUsed,
			}
		case "internalIDP":
			var x InternalIDPUser
			if err = json.Unmarshal(entry.User, &x); err != nil {
				panic(err)
			}
			s.m[k] = SessionEntry{
				User:     x,
				LastUsed: entry.LastUsed,
			}
		default:
			panic("Unknown IDP" + i.IDProvider_)
		}
	}
}
