package proxy

import (
	"sync"
	"time"
)

// SessionInfo is a snapshot of a live brokered session held in the registry.
type SessionInfo struct {
	ID           string
	SubjectType  string
	SubjectID    string
	SubjectLabel string
	Host         string
	Login        string
	Started      time.Time
}

type liveSession struct {
	info  SessionInfo
	close func() // tears down the user and target connections
}

// sessionRegistry tracks this broker's live sessions so they can be enumerated
// and forcibly terminated (ADR-016). It is safe for concurrent use.
type sessionRegistry struct {
	mu sync.Mutex
	m  map[string]*liveSession
}

func newSessionRegistry() *sessionRegistry {
	return &sessionRegistry{m: make(map[string]*liveSession)}
}

func (r *sessionRegistry) add(info SessionInfo, closeFn func()) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.m[info.ID] = &liveSession{info: info, close: closeFn}
}

func (r *sessionRegistry) remove(id string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.m, id)
}

func (r *sessionRegistry) list() []SessionInfo {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]SessionInfo, 0, len(r.m))
	for _, ls := range r.m {
		out = append(out, ls.info)
	}
	return out
}

func (r *sessionRegistry) kill(id string) bool {
	r.mu.Lock()
	ls, ok := r.m[id]
	r.mu.Unlock()
	if !ok {
		return false
	}
	ls.close()
	return true
}

// LiveSessions returns a snapshot of the sessions this broker is currently
// proxying. Used by the revocation reaper and for operational visibility.
func (s *Server) LiveSessions() []SessionInfo { return s.sessions.list() }

// Kill forcibly terminates a live session by closing its user and target
// connections. Returns false if the session is not on this broker. The session
// end is recorded by the normal teardown path once the copy loops unwind.
func (s *Server) Kill(id string) bool { return s.sessions.kill(id) }
