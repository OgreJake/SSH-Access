package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestParseAsciinemaURL(t *testing.T) {
	const server = "http://localhost:4000"
	cases := []struct {
		name   string
		out    string
		want   string
		wantOK bool
	}{
		{
			name:   "classic view-at block",
			out:    "View the recording at:\n\n    http://localhost:4000/a/aZ9.\n",
			want:   "http://localhost:4000/a/aZ9",
			wantOK: true,
		},
		{
			name:   "url on its own line",
			out:    "http://localhost:4000/a/12345\n",
			want:   "http://localhost:4000/a/12345",
			wantOK: true,
		},
		{
			name:   "prefers server url over other links",
			out:    "see docs at https://docs.asciinema.org/ then http://localhost:4000/a/xyz\n",
			want:   "http://localhost:4000/a/xyz",
			wantOK: true,
		},
		{
			name:   "falls back to last url when none match server",
			out:    "uploaded to http://other.example/a/1\n",
			want:   "http://other.example/a/1",
			wantOK: true,
		},
		{
			name:   "no url",
			out:    "upload complete, no link here",
			wantOK: false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := parseAsciinemaURL(c.out, server)
			if c.wantOK && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !c.wantOK {
				if err == nil {
					t.Fatalf("expected error, got %q", got)
				}
				return
			}
			if got != c.want {
				t.Fatalf("got %q, want %q", got, c.want)
			}
		})
	}
}

func TestAsciinemaUploaderExec(t *testing.T) {
	dir := t.TempDir()
	// Fake asciinema CLI that prints a server URL like the real one.
	script := filepath.Join(dir, "asciinema")
	body := "#!/bin/sh\necho \"View the recording at:\"\necho \"    http://localhost:4000/a/fake123\"\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	u := asciinemaUploader{bin: script, serverURL: "http://localhost:4000"}
	url, err := u.Upload(context.Background(), filepath.Join(dir, "sess.cast"))
	if err != nil {
		t.Fatalf("upload: %v", err)
	}
	if url != "http://localhost:4000/a/fake123" {
		t.Fatalf("got %q", url)
	}

	// A failing CLI surfaces an error.
	bad := filepath.Join(dir, "bad")
	if err := os.WriteFile(bad, []byte("#!/bin/sh\necho boom >&2\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := (asciinemaUploader{bin: bad, serverURL: "http://localhost:4000"}).Upload(context.Background(), "x.cast"); err == nil {
		t.Fatal("expected error from failing uploader")
	}
}
