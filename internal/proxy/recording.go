package proxy

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Recorder opens a recording sink for a session. The file backend produces an
// asciinema v2 (.cast) stream; the Nop backend records nothing. Full recording
// is opt-in per grant (ADR-011); only the target→user terminal stream is
// captured (never user keystrokes, which can contain typed secrets).
type Recorder interface {
	Open(sessionID string, width, height int) (Recording, string, error)
}

// Recording is an open session recording. Output is the target's terminal
// stream. Implementations must be safe for concurrent Output/Close.
type Recording interface {
	Output(p []byte)
	Close() error
}

// NopRecorder records nothing and returns an empty ref.
type NopRecorder struct{}

func (NopRecorder) Open(string, int, int) (Recording, string, error) { return nopRecording{}, "", nil }

type nopRecording struct{}

func (nopRecording) Output([]byte) {}
func (nopRecording) Close() error  { return nil }

// FileRecorder writes asciinema v2 .cast files into a directory, one per
// session, named "<sessionID>.cast".
type FileRecorder struct{ dir string }

// NewFileRecorder ensures the directory exists and returns a recorder.
func NewFileRecorder(dir string) (*FileRecorder, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create recording dir %q: %w", dir, err)
	}
	return &FileRecorder{dir: dir}, nil
}

func (r *FileRecorder) Open(sessionID string, width, height int) (Recording, string, error) {
	if width <= 0 {
		width = 80
	}
	if height <= 0 {
		height = 24
	}
	name := sessionID + ".cast"
	f, err := os.OpenFile(filepath.Join(r.dir, name), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, "", fmt.Errorf("create recording: %w", err)
	}
	rec := &castRecording{f: f, enc: json.NewEncoder(f), start: time.Now()}
	// asciinema v2 header line.
	if err := rec.enc.Encode(map[string]any{
		"version": 2, "width": width, "height": height, "timestamp": rec.start.Unix(),
	}); err != nil {
		_ = f.Close()
		return nil, "", fmt.Errorf("write recording header: %w", err)
	}
	return rec, name, nil
}

type castRecording struct {
	mu     sync.Mutex
	f      *os.File
	enc    *json.Encoder
	start  time.Time
	closed bool
}

// Output appends an asciinema "o" (output) event: [elapsed_seconds, "o", data].
func (c *castRecording) Output(p []byte) {
	if len(p) == 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return
	}
	_ = c.enc.Encode([]any{time.Since(c.start).Seconds(), "o", string(p)})
}

func (c *castRecording) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	return c.f.Close()
}

// recWriter adapts a Recording to io.Writer so it can sit in an io.MultiWriter
// alongside the user channel.
type recWriter struct{ rec Recording }

func (w recWriter) Write(p []byte) (int, error) {
	w.rec.Output(p)
	return len(p), nil
}
