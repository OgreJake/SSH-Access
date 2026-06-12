package proxy

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/yourorg/sshbroker/internal/ca"
	"github.com/yourorg/sshbroker/internal/model"
	"github.com/yourorg/sshbroker/internal/signer"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func genHostKey(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "host_key")
	if out, err := exec.Command("ssh-keygen", "-t", "ed25519", "-f", path, "-N", "", "-C", "host").CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen: %v\n%s", err, out)
	}
	return path
}

func genUserKey(t *testing.T) (ssh.Signer, ssh.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	signer, err := ssh.NewSignerFromSigner(priv)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("pub: %v", err)
	}
	return signer, sshPub
}

func newIssuer(t *testing.T) (*ca.Issuer, ssh.PublicKey) {
	t.Helper()
	caPath := filepath.Join(t.TempDir(), "ca_key")
	if out, err := exec.Command("ssh-keygen", "-t", "ecdsa", "-b", "256", "-f", caPath, "-N", "", "-C", "ca").CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen ca: %v\n%s", err, out)
	}
	auth, err := signer.NewFileAuthority(caPath, "")
	if err != nil {
		t.Fatalf("file authority: %v", err)
	}
	iss, err := ca.NewIssuer(auth, ca.NewCounterAllocator(0), 5*time.Minute)
	if err != nil {
		t.Fatalf("issuer: %v", err)
	}
	return iss, iss.CAPublicKey()
}

func keysEqual(a, b ssh.PublicKey) bool { return string(a.Marshal()) == string(b.Marshal()) }

// startTargetServer runs an SSH server that trusts caPub and answers exec/shell
// with a marker, so tests can confirm the command actually reached the target.
func startTargetServer(t *testing.T, caPub ssh.PublicKey) (addr, hostFP string) {
	t.Helper()
	hostPath := genHostKey(t)
	pem, _ := os.ReadFile(hostPath)
	hostSigner, err := ssh.ParsePrivateKey(pem)
	if err != nil {
		t.Fatalf("host signer: %v", err)
	}
	checker := &ssh.CertChecker{IsUserAuthority: func(k ssh.PublicKey) bool { return keysEqual(k, caPub) }}
	cfg := &ssh.ServerConfig{PublicKeyCallback: checker.Authenticate}
	cfg.AddHostKey(hostSigner)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("target listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go serveTarget(c, cfg)
		}
	}()
	return ln.Addr().String(), ssh.FingerprintSHA256(hostSigner.PublicKey())
}

func serveTarget(c net.Conn, cfg *ssh.ServerConfig) {
	defer c.Close()
	sc, chans, reqs, err := ssh.NewServerConn(c, cfg)
	if err != nil {
		return
	}
	defer sc.Close()
	go ssh.DiscardRequests(reqs)
	for nc := range chans {
		if nc.ChannelType() != "session" {
			_ = nc.Reject(ssh.UnknownChannelType, "")
			continue
		}
		ch, creqs, err := nc.Accept()
		if err != nil {
			continue
		}
		go func() {
			defer ch.Close()
			for r := range creqs {
				switch r.Type {
				case "exec":
					var p struct{ Command string }
					_ = ssh.Unmarshal(r.Payload, &p)
					_ = r.Reply(true, nil)
					if p.Command == "block" {
						// Hold the channel open until it is closed, so the
						// session stays live (used to test forced termination).
						_, _ = io.Copy(io.Discard, ch)
						return
					}
					_, _ = io.WriteString(ch, "target-exec: "+p.Command+"\n")
					_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ S uint32 }{0}))
					return
				case "shell":
					_ = r.Reply(true, nil)
					_, _ = io.WriteString(ch, "target-shell\n")
					_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ S uint32 }{0}))
					return
				case "pty-req", "env":
					_ = r.Reply(true, nil)
				default:
					_ = r.Reply(false, nil)
				}
			}
		}()
	}
}

func writeTargets(t *testing.T, host, addr, hostFP, subject string, principals []string, shell, exec, sftp bool) string {
	t.Helper()
	doc := map[string]any{"targets": []any{map[string]any{
		"name": host, "address": addr, "host_key": hostFP,
		"grants": []any{map[string]any{
			"subject": subject, "principals": principals, "max_ttl": "5m",
			"shell": shell, "exec": exec, "sftp": sftp,
		}},
	}}}
	b, _ := json.MarshalIndent(doc, "", "  ")
	path := filepath.Join(t.TempDir(), "targets.json")
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatalf("write targets: %v", err)
	}
	return path
}

func startBroker(t *testing.T, auth Authenticator, authz Authorizer, iss *ca.Issuer) (*Server, string) {
	return startBrokerWithAuditor(t, auth, authz, iss, NopAuditor)
}

func startBrokerWithAuditor(t *testing.T, auth Authenticator, authz Authorizer, iss *ca.Issuer, aud Auditor) (*Server, string) {
	t.Helper()
	srv, err := New(Config{
		HostKeyPath:   genHostKey(t),
		Authenticator: auth,
		Authorizer:    authz,
		Issuer:        iss,
		Auditor:       aud,
		Logger:        discardLogger(),
	})
	if err != nil {
		t.Fatalf("New broker: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("broker listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = srv.Serve(ctx, ln) }()
	return srv, ln.Addr().String()
}

func clientConfig(user string, signer ssh.Signer, hostKey ssh.PublicKey) *ssh.ClientConfig {
	return &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.FixedHostKey(hostKey),
		Timeout:         5 * time.Second,
	}
}

func dialBroker(t *testing.T, srv *Server, addr, user string, signer ssh.Signer) *ssh.Client {
	t.Helper()
	client, err := ssh.Dial("tcp", addr, clientConfig(user, signer, srv.HostPublicKey()))
	if err != nil {
		t.Fatalf("dial broker: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

// TestBrokeredExecEndToEnd: client -> broker -> target, full chain.
func TestBrokeredExecEndToEnd(t *testing.T) {
	iss, caPub := newIssuer(t)
	targetAddr, targetFP := startTargetServer(t, caPub)

	userSigner, userPub := genUserKey(t)
	auth := NewMemoryAuthenticator()
	auth.Add(userPub, Identity{Subject: model.SubjectUser, ID: "alice", Label: "alice"})

	authz, err := LoadTargets(writeTargets(t, "web01", targetAddr, targetFP, "alice", []string{"deploy"}, true, true, false))
	if err != nil {
		t.Fatalf("LoadTargets: %v", err)
	}
	srv, brokerAddr := startBroker(t, auth, authz, iss)

	client := dialBroker(t, srv, brokerAddr, "deploy+web01", userSigner)
	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	defer sess.Close()

	out, err := sess.Output("whoami")
	if err != nil {
		t.Fatalf("exec through broker: %v", err)
	}
	if !contains(string(out), "target-exec: whoami") {
		t.Fatalf("unexpected target output: %q", string(out))
	}
}

func TestUnauthorizedPrincipalRejected(t *testing.T) {
	iss, caPub := newIssuer(t)
	targetAddr, targetFP := startTargetServer(t, caPub)
	userSigner, userPub := genUserKey(t)
	auth := NewMemoryAuthenticator()
	auth.Add(userPub, Identity{Subject: model.SubjectUser, ID: "alice", Label: "alice"})
	// alice may use "deploy", not "root".
	authz, _ := LoadTargets(writeTargets(t, "web01", targetAddr, targetFP, "alice", []string{"deploy"}, true, true, false))
	srv, brokerAddr := startBroker(t, auth, authz, iss)

	client := dialBroker(t, srv, brokerAddr, "root+web01", userSigner)
	sess, _ := client.NewSession()
	defer sess.Close()
	if _, err := sess.Output("whoami"); err == nil {
		t.Fatal("expected non-zero exit for unauthorized principal")
	}
}

func TestExecCapabilityDenied(t *testing.T) {
	iss, caPub := newIssuer(t)
	targetAddr, targetFP := startTargetServer(t, caPub)
	userSigner, userPub := genUserKey(t)
	auth := NewMemoryAuthenticator()
	auth.Add(userPub, Identity{Subject: model.SubjectUser, ID: "alice", Label: "alice"})
	// exec=false: the broker must refuse the exec request.
	authz, _ := LoadTargets(writeTargets(t, "web01", targetAddr, targetFP, "alice", []string{"deploy"}, true, false, false))
	srv, brokerAddr := startBroker(t, auth, authz, iss)

	client := dialBroker(t, srv, brokerAddr, "deploy+web01", userSigner)
	sess, _ := client.NewSession()
	defer sess.Close()
	if err := sess.Run("whoami"); err == nil {
		t.Fatal("expected exec to be denied by capability gating")
	}
}

func TestBadTargetSpecRejected(t *testing.T) {
	iss, _ := newIssuer(t)
	userSigner, userPub := genUserKey(t)
	auth := NewMemoryAuthenticator()
	auth.Add(userPub, Identity{Subject: model.SubjectUser, ID: "alice", Label: "alice"})
	srv, brokerAddr := startBroker(t, auth, NewMemoryAuthorizer(), iss)

	client := dialBroker(t, srv, brokerAddr, "web01", userSigner) // no "+login"
	sess, _ := client.NewSession()
	defer sess.Close()
	if _, err := sess.Output("whoami"); err == nil {
		t.Fatal("expected error for malformed target spec")
	}
}

func TestUnregisteredKeyRejected(t *testing.T) {
	iss, _ := newIssuer(t)
	_, registeredPub := genUserKey(t)
	auth := NewMemoryAuthenticator()
	auth.Add(registeredPub, Identity{Subject: model.SubjectUser, ID: "alice", Label: "alice"})
	srv, brokerAddr := startBroker(t, auth, NewMemoryAuthorizer(), iss)

	otherSigner, _ := genUserKey(t)
	if _, err := ssh.Dial("tcp", brokerAddr, clientConfig("deploy+web01", otherSigner, srv.HostPublicKey())); err == nil {
		t.Fatal("dial should fail for an unregistered key")
	}
}

func TestLoadAuthorizedUsers(t *testing.T) {
	_, pub := genUserKey(t)
	line := string(ssh.MarshalAuthorizedKey(pub))
	entry := line[:len(line)-1] + " bob\n"
	path := filepath.Join(t.TempDir(), "authorized_users")
	if err := os.WriteFile(path, []byte(entry), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	au, err := LoadAuthorizedUsers(path)
	if err != nil {
		t.Fatalf("LoadAuthorizedUsers: %v", err)
	}
	id, err := au.AuthenticatePublicKey(pub)
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if id.Label != "bob" {
		t.Fatalf("label = %q, want bob", id.Label)
	}
}

type recordingAuditor struct {
	mu      sync.Mutex
	started []SessionRecord
	ended   []SessionOutcome
}

func (r *recordingAuditor) StartSession(_ context.Context, rec SessionRecord) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.started = append(r.started, rec)
	return "sess-test", nil
}
func (r *recordingAuditor) EndSession(_ context.Context, _ string, o SessionOutcome) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.ended = append(r.ended, o)
	return nil
}
func (r *recordingAuditor) RecordEvent(context.Context, Event) {}

func (r *recordingAuditor) counts() (int, int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.started), len(r.ended)
}

func TestBrokeredSessionIsAudited(t *testing.T) {
	iss, caPub := newIssuer(t)
	targetAddr, targetFP := startTargetServer(t, caPub)
	userSigner, userPub := genUserKey(t)
	auth := NewMemoryAuthenticator()
	auth.Add(userPub, Identity{Subject: model.SubjectUser, ID: "alice", Label: "alice"})
	authz, _ := LoadTargets(writeTargets(t, "web01", targetAddr, targetFP, "alice", []string{"deploy"}, true, true, false))

	rec := &recordingAuditor{}
	srv, brokerAddr := startBrokerWithAuditor(t, auth, authz, iss, rec)

	client := dialBroker(t, srv, brokerAddr, "deploy+web01", userSigner)
	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	if _, err := sess.Output("whoami"); err != nil {
		t.Fatalf("exec: %v", err)
	}
	_ = sess.Close()

	// StartSession happens before proxying.
	if s, _ := rec.counts(); s != 1 {
		t.Fatalf("expected 1 StartSession, got %d", s)
	}
	if rec.started[0].Host != "web01" || rec.started[0].Login != "deploy" {
		t.Fatalf("unexpected session record: %+v", rec.started[0])
	}
	if rec.started[0].CertSerial == 0 {
		t.Fatal("expected a non-zero cert serial in the session record")
	}

	// EndSession happens when the connection closes.
	_ = client.Close()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, e := rec.counts(); e == 1 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if _, e := rec.counts(); e != 1 {
		t.Fatalf("expected 1 EndSession, got %d", e)
	}
	if rec.ended[0].BytesOut == 0 {
		t.Fatal("expected non-zero bytes_out from the target's output")
	}
	if rec.ended[0].ExitStatus == nil || *rec.ended[0].ExitStatus != 0 {
		t.Fatalf("expected exit status 0, got %v", rec.ended[0].ExitStatus)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func TestBrokeredSessionKill(t *testing.T) {
	iss, caPub := newIssuer(t)
	targetAddr, targetFP := startTargetServer(t, caPub)
	userSigner, userPub := genUserKey(t)
	auth := NewMemoryAuthenticator()
	auth.Add(userPub, Identity{Subject: model.SubjectUser, ID: "alice", Label: "alice"})
	authz, _ := LoadTargets(writeTargets(t, "web01", targetAddr, targetFP, "alice", []string{"deploy"}, true, true, false))
	rec := &recordingAuditor{}
	srv, brokerAddr := startBrokerWithAuditor(t, auth, authz, iss, rec)

	client := dialBroker(t, srv, brokerAddr, "deploy+web01", userSigner)
	defer client.Close()
	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	// A command that blocks keeps the session live until forcibly closed.
	if err := sess.Start("block"); err != nil {
		t.Fatalf("start: %v", err)
	}

	// Wait for the broker to register the live session.
	var id string
	for i := 0; i < 200; i++ {
		if live := srv.LiveSessions(); len(live) == 1 {
			id = live[0].ID
			if live[0].SubjectLabel != "alice" {
				t.Fatalf("live session subject = %q", live[0].SubjectLabel)
			}
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if id == "" {
		t.Fatal("session never registered as live")
	}

	if !srv.Kill(id) {
		t.Fatal("Kill returned false for a live session")
	}

	// The blocked command should now return and the session should end.
	done := make(chan error, 1)
	go func() { done <- sess.Wait() }()
	select {
	case <-done: // returned (with an error) because the connection was torn down
	case <-time.After(2 * time.Second):
		t.Fatal("session did not end after Kill")
	}

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if _, e := rec.counts(); e == 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, e := rec.counts(); e != 1 {
		t.Fatalf("expected 1 EndSession after kill, got %d", e)
	}
	if n := len(srv.LiveSessions()); n != 0 {
		t.Fatalf("registry should be empty after kill, has %d", n)
	}
}

func startBrokerWithRecorder(t *testing.T, auth Authenticator, authz Authorizer, iss *ca.Issuer, aud Auditor, rec Recorder) (*Server, string) {
	t.Helper()
	srv, err := New(Config{
		HostKeyPath: genHostKey(t), Authenticator: auth, Authorizer: authz,
		Issuer: iss, Auditor: aud, Recorder: rec, Logger: discardLogger(),
	})
	if err != nil {
		t.Fatalf("New broker: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("broker listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = srv.Serve(ctx, ln) }()
	return srv, ln.Addr().String()
}

// fixedAuthorizer returns a preset Decision (used to exercise recording without
// standing up the DB authorizer).
type fixedAuthorizer struct{ d *Decision }

func (f fixedAuthorizer) Authorize(context.Context, Identity, TargetSpec) (*Decision, error) {
	return f.d, nil
}

func TestBrokeredSessionRecording(t *testing.T) {
	iss, caPub := newIssuer(t)
	targetAddr, targetFP := startTargetServer(t, caPub)
	userSigner, userPub := genUserKey(t)
	auth := NewMemoryAuthenticator()
	auth.Add(userPub, Identity{Subject: model.SubjectUser, ID: "alice", Label: "alice"})
	authz := fixedAuthorizer{d: &Decision{
		Address: targetAddr, HostKeyFingerprint: targetFP, Login: "deploy",
		Principals: []string{"deploy"}, AllowExec: true, AllowShell: true,
		Recording: "full", TTL: 2 * time.Minute,
	}}
	dir := t.TempDir()
	fr, err := NewFileRecorder(dir)
	if err != nil {
		t.Fatalf("recorder: %v", err)
	}
	rec := &recordingAuditor{}
	srv, brokerAddr := startBrokerWithRecorder(t, auth, authz, iss, rec, fr)

	client := dialBroker(t, srv, brokerAddr, "deploy+web01", userSigner)
	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	out, err := sess.Output("whoami")
	if err != nil {
		t.Fatalf("exec: %v", err)
	}
	if !strings.Contains(string(out), "target-exec: whoami") {
		t.Fatalf("unexpected exec output: %q", out)
	}
	_ = client.Close() // unwinds handleConn, closing the recording

	// recordingAuditor returns sessionID "sess-test" → sess-test.cast.
	path := filepath.Join(dir, "sess-test.cast")
	var data []byte
	for i := 0; i < 200; i++ {
		data, err = os.ReadFile(path)
		if err == nil && len(data) > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("read recording: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	var header map[string]any
	if jerr := json.Unmarshal([]byte(lines[0]), &header); jerr != nil {
		t.Fatalf("parse cast header: %v (line %q)", jerr, lines[0])
	}
	if v, _ := header["version"].(float64); v != 2 {
		t.Fatalf("expected asciinema v2 header, got %v", header["version"])
	}
	if !strings.Contains(string(data), "target-exec: whoami") {
		t.Fatalf("recording does not contain target output:\n%s", data)
	}
}
