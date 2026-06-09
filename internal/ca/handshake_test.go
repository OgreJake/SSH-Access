package ca

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// loadUserSigner generates a user keypair and returns its private signer plus
// public key, so the test can both request a cert and authenticate with it.
func loadUserSigner(t *testing.T) (ssh.Signer, ssh.PublicKey) {
	t.Helper()
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "user_key")
	run(t, "ssh-keygen", "-t", "ed25519", "-f", keyPath, "-N", "", "-C", "user")
	priv, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read key: %v", err)
	}
	s, err := ssh.ParsePrivateKey(priv)
	if err != nil {
		t.Fatalf("parse key: %v", err)
	}
	return s, s.PublicKey()
}

// startTestSSHServer starts an SSH server on 127.0.0.1 that trusts caPubKey
// and accepts user certificates. It returns the listen address and the server
// host public key (for the client's HostKeyCallback).
func startTestSSHServer(t *testing.T, caPubKey ssh.PublicKey) (string, ssh.PublicKey) {
	t.Helper()

	// Host key for the server.
	dir := t.TempDir()
	hostPath := filepath.Join(dir, "host_key")
	run(t, "ssh-keygen", "-t", "ed25519", "-f", hostPath, "-N", "", "-C", "host")
	hostPEM, err := os.ReadFile(hostPath)
	if err != nil {
		t.Fatalf("read host key: %v", err)
	}
	hostSigner, err := ssh.ParsePrivateKey(hostPEM)
	if err != nil {
		t.Fatalf("parse host key: %v", err)
	}

	checker := &ssh.CertChecker{
		IsUserAuthority: func(k ssh.PublicKey) bool { return keysEqual(k, caPubKey) },
	}
	cfg := &ssh.ServerConfig{
		// Authenticate enforces CA trust, principal == conn.User(), validity,
		// and (via the returned Permissions) the source-address option.
		PublicKeyCallback: checker.Authenticate,
	}
	cfg.AddHostKey(hostSigner)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return // listener closed
			}
			go func() {
				defer conn.Close()
				sc, chans, reqs, err := ssh.NewServerConn(conn, cfg)
				if err != nil {
					return // auth failed (expected in negative tests)
				}
				defer sc.Close()
				go ssh.DiscardRequests(reqs)
				for nc := range chans {
					_ = nc.Reject(ssh.Prohibited, "test server")
				}
			}()
		}
	}()

	return ln.Addr().String(), hostSigner.PublicKey()
}

// dialWithCert attempts an SSH handshake using cert + userSigner as the given
// login. It returns nil on a successful authenticated handshake.
func dialWithCert(addr, login string, cert *ssh.Certificate, userSigner ssh.Signer, hostKey ssh.PublicKey) error {
	certSigner, err := ssh.NewCertSigner(cert, userSigner)
	if err != nil {
		return err
	}
	cfg := &ssh.ClientConfig{
		User:            login,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(certSigner)},
		HostKeyCallback: ssh.FixedHostKey(hostKey),
		Timeout:         5 * time.Second,
	}
	client, err := ssh.Dial("tcp", addr, cfg)
	if err != nil {
		return err
	}
	_ = client.Close()
	return nil
}

// TestHandshakeEndToEnd proves that a freshly issued certificate is accepted
// by a real SSH server that trusts only the CA — and that principal and
// source-address constraints are enforced during the handshake.
func TestHandshakeEndToEnd(t *testing.T) {
	i := newIssuer(t, 5*time.Minute)
	userSigner, userPub := loadUserSigner(t)
	addr, hostKey := startTestSSHServer(t, i.CAPublicKey())

	t.Run("valid cert authenticates", func(t *testing.T) {
		cert, err := i.Issue(context.Background(), IssueParams{
			UserPublicKey: userPub,
			Principals:    []string{"deploy"},
			TTL:           2 * time.Minute,
			KeyID:         "req-ok:alice",
			SourceAddress: "127.0.0.1/32", // matches loopback dialer
			Permissions:   Permissions{PTY: true},
		})
		if err != nil {
			t.Fatalf("Issue: %v", err)
		}
		if err := dialWithCert(addr, "deploy", cert, userSigner, hostKey); err != nil {
			t.Fatalf("handshake should succeed: %v", err)
		}
	})

	t.Run("wrong login rejected", func(t *testing.T) {
		cert, err := i.Issue(context.Background(), IssueParams{
			UserPublicKey: userPub,
			Principals:    []string{"deploy"},
			TTL:           2 * time.Minute,
			KeyID:         "req-wrong-login:alice",
			Permissions:   Permissions{PTY: true},
		})
		if err != nil {
			t.Fatalf("Issue: %v", err)
		}
		// Cert is valid for "deploy" but we log in as "root".
		if err := dialWithCert(addr, "root", cert, userSigner, hostKey); err == nil {
			t.Fatal("handshake should fail for a non-authorized login")
		}
	})

	t.Run("source-address pin enforced", func(t *testing.T) {
		cert, err := i.Issue(context.Background(), IssueParams{
			UserPublicKey: userPub,
			Principals:    []string{"deploy"},
			TTL:           2 * time.Minute,
			KeyID:         "req-srcaddr:alice",
			SourceAddress: "10.99.99.99/32", // does NOT match loopback dialer
			Permissions:   Permissions{PTY: true},
		})
		if err != nil {
			t.Fatalf("Issue: %v", err)
		}
		if err := dialWithCert(addr, "deploy", cert, userSigner, hostKey); err == nil {
			t.Fatal("handshake should fail: source address not permitted")
		}
	})
}
