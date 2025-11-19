package main

import (
	"encoding/json"
	"math/rand"
	"os"
	"sync"
	"time"
)

func randomString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}
func NewSessionID() string {
	return randomString(32)
}

type SessionEntry struct {
	User     User
	LastUsed time.Time
}

func NewSessionEntry(u User) SessionEntry {
	return SessionEntry{
		User:     u,
		LastUsed: time.Now(),
	}
}

type SessionStore struct {
	sync.RWMutex
	m map[string]SessionEntry
}

func NewSessionStore() *SessionStore {
	return &SessionStore{
		m: make(map[string]SessionEntry, 16),
	}
}
func NewSessionStoreFromFile(fname string) *SessionStore {
	s := NewSessionStore()
	buf, err := os.ReadFile(fname)
	if err != nil {
		return s

	}
	s.FromJson(buf)
	return s
}

func (s *SessionStore) PruneOldSessions(olderthan time.Duration) {
	s.Lock()
	defer s.Unlock()
	for k, v := range s.m {
		if v.LastUsed.Add(olderthan).Before(time.Now()) {
			delete(s.m, k)
		}
	}
}

func (s *SessionStore) AddSessionEntry(sessionID string, se SessionEntry) {
	s.Lock()
	s.m[sessionID] = se
	s.Unlock()
}

func (s *SessionStore) DeleteSessionEntry(sessionID string) {
	s.Lock()
	delete(s.m, sessionID)
	s.Unlock()
}

func (s *SessionStore) GetSessionEntry(sessionID string) (SessionEntry, bool) {
	s.RLock()
	se, ok := sessions.m[sessionID]
	s.RUnlock()
	return se, ok
}

func (s *SessionStore) Add(sessionID string, u User) {
	se := SessionEntry{
		User:     u,
		LastUsed: time.Now(),
	}
	s.Lock()
	s.m[sessionID] = se
	s.Unlock()
}

func (s *SessionStore) TouchLastUsed(sessionID string) {
	s.Lock()
	se, ok := s.m[sessionID]
	if !ok {
		logger.Warn("Session to touch does not exist in SessionStore: " + sessionID)
	}
	se.LastUsed = time.Now()
	s.m[sessionID] = se
	s.Unlock()
}

func (s *SessionStore) ToJson() []byte {
	s.RLock()
	defer s.RUnlock()
	sj, err := json.MarshalIndent(s.m, "", "   ")
	if err != nil {
		return nil
	}
	return sj
}

func (s *SessionStore) FromJson(sj []byte) {
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
