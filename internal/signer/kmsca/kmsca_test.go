package kmsca

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"golang.org/x/crypto/ssh"
)

// fakeKMS mimics a KMS ECC_NIST_P256 SIGN_VERIFY key using a local key. It
// reproduces the two behaviours this package depends on: GetPublicKey returns
// the key as PKIX DER, and Sign returns an ASN.1-DER ECDSA signature over a
// pre-computed digest — exactly what real KMS returns.
type fakeKMS struct {
	priv     *ecdsa.PrivateKey
	der      []byte
	keyUsage types.KeyUsageType
	keySpec  types.KeySpec
	lastIn   *kms.SignInput
}

func newFakeKMS(t *testing.T) *fakeKMS {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("marshal pkix: %v", err)
	}
	return &fakeKMS{
		priv:     priv,
		der:      der,
		keyUsage: types.KeyUsageTypeSignVerify,
		keySpec:  types.KeySpecEccNistP256,
	}
}

func (f *fakeKMS) GetPublicKey(_ context.Context, _ *kms.GetPublicKeyInput, _ ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
	return &kms.GetPublicKeyOutput{
		PublicKey: f.der,
		KeyUsage:  f.keyUsage,
		KeySpec:   f.keySpec,
	}, nil
}

func (f *fakeKMS) Sign(_ context.Context, in *kms.SignInput, _ ...func(*kms.Options)) (*kms.SignOutput, error) {
	f.lastIn = in
	sig, err := ecdsa.SignASN1(rand.Reader, f.priv, in.Message) // Message is the digest
	if err != nil {
		return nil, err
	}
	return &kms.SignOutput{Signature: sig}, nil
}

func newUserCert(t *testing.T) (*ssh.Certificate, ssh.PublicKey) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen user key: %v", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("ssh pub: %v", err)
	}
	now := time.Now()
	return &ssh.Certificate{
		Key:             sshPub,
		Serial:          1,
		CertType:        ssh.UserCert,
		KeyId:           "test:alice",
		ValidPrincipals: []string{"alice"},
		ValidAfter:      uint64(now.Add(-time.Minute).Unix()),
		ValidBefore:     uint64(now.Add(2 * time.Minute).Unix()),
		Permissions:     ssh.Permissions{Extensions: map[string]string{"permit-pty": ""}},
	}, sshPub
}

func TestNewLoadsPublicKey(t *testing.T) {
	f := newFakeKMS(t)
	a, err := New(context.Background(), "alias/test", withClient(f))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	want, _ := ssh.NewPublicKey(&f.priv.PublicKey)
	if string(a.PublicKey().Marshal()) != string(want.Marshal()) {
		t.Fatal("authority public key does not match the KMS key")
	}
}

func TestNewRejectsWrongKeyUsage(t *testing.T) {
	f := newFakeKMS(t)
	f.keyUsage = types.KeyUsageTypeEncryptDecrypt
	if _, err := New(context.Background(), "k", withClient(f)); err == nil {
		t.Fatal("expected error for non-SIGN_VERIFY key")
	}
}

func TestNewRejectsWrongKeySpec(t *testing.T) {
	f := newFakeKMS(t)
	f.keySpec = types.KeySpecRsa2048
	if _, err := New(context.Background(), "k", withClient(f)); err == nil {
		t.Fatal("expected error for non-ECC_NIST_P256 key")
	}
}

func TestSignCertificateProducesValidCert(t *testing.T) {
	f := newFakeKMS(t)
	a, err := New(context.Background(), "k", withClient(f))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	cert, _ := newUserCert(t)
	if err := a.SignCertificate(context.Background(), cert); err != nil {
		t.Fatalf("SignCertificate: %v", err)
	}

	// KMS must have been asked to sign a digest with ECDSA_SHA_256.
	if f.lastIn.MessageType != types.MessageTypeDigest {
		t.Errorf("MessageType = %q, want DIGEST", f.lastIn.MessageType)
	}
	if f.lastIn.SigningAlgorithm != types.SigningAlgorithmSpecEcdsaSha256 {
		t.Errorf("SigningAlgorithm = %q, want ECDSA_SHA_256", f.lastIn.SigningAlgorithm)
	}

	// The signed certificate must validate against the CA via a CertChecker.
	checker := &ssh.CertChecker{
		IsUserAuthority: func(k ssh.PublicKey) bool {
			return string(k.Marshal()) == string(a.PublicKey().Marshal())
		},
	}
	if err := checker.CheckCert("alice", cert); err != nil {
		t.Fatalf("CheckCert(alice): %v", err)
	}
	if err := checker.CheckCert("eve", cert); err == nil {
		t.Fatal("CheckCert(eve) should fail")
	}
}
