package api

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/yourorg/sshbroker/internal/store"
)

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// writeErrorExtra writes an error response that includes additional key/value
// fields alongside "error". Values must be JSON-serialisable. Used by auth
// guards to return auth_url on 401 so the SPA can construct the SSO link
// without knowing the auth domain at build time.
func writeErrorExtra(w http.ResponseWriter, status int, msg string, extra map[string]any) {
	body := map[string]any{"error": msg}
	for k, v := range extra {
		body[k] = v
	}
	writeJSON(w, status, body)
}

// decode parses a JSON request body, rejecting unknown fields.
func decode(r *http.Request, dst any) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	return dec.Decode(dst)
}

// writeStoreError maps a store error to an HTTP status.
func writeStoreError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "not found")
	case store.IsConflict(err):
		writeError(w, http.StatusConflict, "already exists")
	default:
		// Log the real error server-side (CC7.2/CC7.3) but return a generic
		// message so internals aren't leaked to the client.
		slog.Default().Error("unexpected store error", "err", err.Error())
		writeError(w, http.StatusInternalServerError, "internal error")
	}
}
