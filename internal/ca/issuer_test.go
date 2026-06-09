package ca

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/yourorg/sshbroker/internal/signer"
)

// testAuthority generates an ECDSA P-256 CA key and returns a FileAuthority.
func testAuthority(t *testing.T) *signer.FileAuthority {
	t.Helper()
	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca_key")
	run(t, "ssh-keygen", "-t", "ecdsa", "-b", "256", "-f", caPath, "-N", "", "-C", "test-ca")
	a, err := signer.NewFileAuthority(caPath, "")
	if err != nil {
		t.Fatalf("NewFileAuthority: %v", err)
	}
	return a
}

// testUserKey generates an ed25519 key and returns its public half.
func testUserKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "user_key")
	run(t, "ssh-keygen", "-t", "ed25519", "-f", keyPath, "-N", "", "-C", "user")
	pubBytes, err := os.ReadFile(keyPath + ".pub")
	if err != nil {
		t.Fatalf("read pub: %v", err)
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey(pubBytes)
	if err != nil {
		t.Fatalf("parse pub: %v", err)
	}
	return pub
}

func run(t *testing.T, name string, args ...string) {
	t.Helper()
	if out, err := exec.Command(name, args...).CombinedOutput(); err != nil {
		t.Fatalf("%s: %v\n%s", name, err, out)
	}
}

func newIssuer(t *testing.T, maxTTL time.Duration, opts ...Option) *Issuer {
	t.Helper()
	i, err := NewIssuer(testAuthority(t), NewCounterAllocator(0), maxTTL, opts...)
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}
	return i
}

func baseParams(t *testing.T) IssueParams {
	return IssueParams{
		UserPublicKey: testUserKey(t),
		Principals:    []string{"deploy"},
		TTL:           2 * time.Minute,
		KeyID:         "req-1:alice",
		Permissions:   Permissions{PTY: true},
	}
}

func TestIssueRejectsEmptyPrincipals(t *testing.T) {
	i := newIssuer(t, 5*time.Minute)
	p := baseParams(t)
	p.Principals = []string{"", ""}
	if _, err := i.Issue(context.Background(), p); err == nil {
		t.Fatal("expected error for empty principals")
	}
}

func TestIssueRejectsNilKey(t *testing.T) {
	i := newIssuer(t, 5*time.Minute)
	p := baseParams(t)
	p.UserPublicKey = nil
	if _, err := i.Issue(context.Background(), p); err == nil {
		t.Fatal("expected error for nil key")
	}
}

func TestIssueRequiresKeyID(t *testing.T) {
	i := newIssuer(t, 5*time.Minute)
	p := baseParams(t)
	p.KeyID = ""
	if _, err := i.Issue(context.Background(), p); err == nil {
		t.Fatal("expected error for empty KeyID")
	}
}

func TestIssueClampsTTL(t *testing.T) {
	max := 5 * time.Minute
	skew := 30 * time.Second
	i := newIssuer(t, max, WithClockSkew(skew))
	p := baseParams(t)
	p.TTL = time.Hour // over the cap

	cert, err := i.Issue(context.Background(), p)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	span := time.Duration(cert.ValidBefore-cert.ValidAfter) * time.Second
	want := max + skew
	if span != want {
		t.Fatalf("validity span = %s, want %s (maxTTL clamp + skew)", span, want)
	}
}

func TestIssueLeastPrivilegeExtensions(t *testing.T) {
	i := newIssuer(t, 5*time.Minute)

	// Default capabilities: only PTY.
	cert, err := i.Issue(context.Background(), baseParams(t))
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if _, ok := cert.Extensions[extPTY]; !ok {
		t.Error("expected permit-pty")
	}
	if _, ok := cert.Extensions[extPortForwarding]; ok {
		t.Error("port forwarding should be off by default")
	}
	if _, ok := cert.Extensions[extAgentForwarding]; ok {
		t.Error("agent forwarding should be off by default")
	}

	// Explicitly enabling forwarding adds the extension.
	p := baseParams(t)
	p.Permissions = Permissions{PTY: true, PortForwarding: true}
	cert, err = i.Issue(context.Background(), p)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if _, ok := cert.Extensions[extPortForwarding]; !ok {
		t.Error("expected permit-port-forwarding when enabled")
	}
}

func TestIssueSetsSourceAddress(t *testing.T) {
	i := newIssuer(t, 5*time.Minute)
	p := baseParams(t)
	p.SourceAddress = "10.0.0.5/32"
	cert, err := i.Issue(context.Background(), p)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if got := cert.CriticalOptions[optSourceAddress]; got != "10.0.0.5/32" {
		t.Fatalf("source-address = %q, want 10.0.0.5/32", got)
	}
}

func TestIssueSerialMonotonic(t *testing.T) {
	i := newIssuer(t, 5*time.Minute)
	c1, err := i.Issue(context.Background(), baseParams(t))
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	c2, err := i.Issue(context.Background(), baseParams(t))
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if c2.Serial <= c1.Serial {
		t.Fatalf("serials not increasing: %d then %d", c1.Serial, c2.Serial)
	}
}

func TestIssueAcceptedByCertChecker(t *testing.T) {
	i := newIssuer(t, 5*time.Minute)
	cert, err := i.Issue(context.Background(), baseParams(t))
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	checker := &ssh.CertChecker{
		IsUserAuthority: func(k ssh.PublicKey) bool {
			return keysEqual(k, i.CAPublicKey())
		},
	}
	if err := checker.CheckCert("deploy", cert); err != nil {
		t.Fatalf("CheckCert(deploy): %v", err)
	}
	if err := checker.CheckCert("root", cert); err == nil {
		t.Fatal("CheckCert(root) should fail: not a valid principal")
	}
}

func TestIssueExpiredRejected(t *testing.T) {
	// Issue with a clock 10 minutes in the past and a 5-minute cap, so the
	// certificate is already expired relative to now.
	past := func() time.Time { return time.Now().Add(-10 * time.Minute) }
	i := newIssuer(t, 5*time.Minute, WithClock(past))
	cert, err := i.Issue(context.Background(), baseParams(t))
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	checker := &ssh.CertChecker{
		IsUserAuthority: func(k ssh.PublicKey) bool { return keysEqual(k, i.CAPublicKey()) },
	}
	if err := checker.CheckCert("deploy", cert); err == nil {
		t.Fatal("expected expired certificate to be rejected")
	}
}

func keysEqual(a, b ssh.PublicKey) bool {
	return string(a.Marshal()) == string(b.Marshal())
}
