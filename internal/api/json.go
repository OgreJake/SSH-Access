package api

import (
	"encoding/json"
	"errors"
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
		writeError(w, http.StatusInternalServerError, "internal error")
	}
}
