package main

import (
	"context"
	"fmt"
	"net/url"
	"os/exec"
	"regexp"
	"strings"
)

// recordingUploader uploads a finished .cast file and returns its playback URL.
type recordingUploader interface {
	Upload(ctx context.Context, path string) (string, error)
}

// asciinemaUploader shells out to the asciinema CLI to upload a recording to a
// self-hosted asciinema server (ADR-011):
//
//	asciinema upload <path> --server-url <serverURL>
type asciinemaUploader struct {
	bin       string
	serverURL string
}

func (u asciinemaUploader) Upload(ctx context.Context, path string) (string, error) {
	bin := u.bin
	if bin == "" {
		bin = "asciinema"
	}
	cmd := exec.CommandContext(ctx, bin, "upload", path, "--server-url", u.serverURL)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("asciinema upload: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return parseAsciinemaURL(string(out), u.serverURL)
}

var urlRe = regexp.MustCompile(`https?://[^\s"'<>]+`)

// parseAsciinemaURL extracts the playback URL from asciinema upload output.
// It prefers a URL under the configured server, else the last URL printed.
func parseAsciinemaURL(output, serverURL string) (string, error) {
	matches := urlRe.FindAllString(output, -1)
	if len(matches) == 0 {
		return "", fmt.Errorf("no URL in asciinema output: %q", strings.TrimSpace(output))
	}
	trim := func(s string) string { return strings.TrimRight(s, ".,)\u00a0") }
	if base := strings.TrimRight(serverURL, "/"); base != "" {
		for i := len(matches) - 1; i >= 0; i-- {
			if strings.HasPrefix(matches[i], base) {
				return trim(matches[i]), nil
			}
		}
	}
	return trim(matches[len(matches)-1]), nil
}

// toURIPath reduces a full URL to its path (plus query/fragment). We store only
// the path; the API prepends the configured asciinema viewer origin
// (SSHBROKER_ASCIINEMA_PUBLIC_URL) at read time, so the stored value stays
// origin-independent and existing rows survive a viewer move (ADR-011). The
// asciinema server now lives on its own subdomain behind oauth2-proxy; uploads
// still target the local server, only the viewing origin differs.
func toURIPath(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Path == "" {
		return raw
	}
	p := u.Path
	if u.RawQuery != "" {
		p += "?" + u.RawQuery
	}
	if u.Fragment != "" {
		p += "#" + u.Fragment
	}
	return p
}
