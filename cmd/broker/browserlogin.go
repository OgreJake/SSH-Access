package main

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/yourorg/sshbroker/internal/auth"
	"github.com/yourorg/sshbroker/internal/model"
	"github.com/yourorg/sshbroker/internal/proxy"
	"github.com/yourorg/sshbroker/internal/store"
)

// browserLoginAdapter implements proxy.BrowserLogin over the store (ADR-021):
// it creates/polls/consumes ssh_login_requests and resolves the approved Entra
// subject to a broker user (JIT-provisioning per config).
type browserLoginAdapter struct {
	st       *store.Store
	logger   *slog.Logger
	baseURL  string
	loginTTL time.Duration
	jit      bool
}

func (b browserLoginAdapter) Begin(ctx context.Context, sourceIP, requestedTarget string) (string, string, error) {
	code, hash, err := auth.NewLoginCode()
	if err != nil {
		return "", "", err
	}
	id, err := b.st.CreateSSHLoginRequest(ctx, hash, sourceIP, requestedTarget, time.Now().Add(b.loginTTL))
	if err != nil {
		return "", "", err
	}
	url := strings.TrimRight(b.baseURL, "/") + "/ssh-login?code=" + code
	return id, url, nil
}

func (b browserLoginAdapter) Poll(ctx context.Context, id string) (string, string, error) {
	return b.st.PollSSHLogin(ctx, id)
}

func (b browserLoginAdapter) Consume(ctx context.Context, id string) (string, error) {
	return b.st.ConsumeSSHLogin(ctx, id)
}

func (b browserLoginAdapter) Resolve(ctx context.Context, subject string) (*proxy.Identity, error) {
	u, err := b.st.GetUserBySubject(ctx, subject)
	if errors.Is(err, store.ErrNotFound) {
		if !b.jit {
			b.logger.Info("ssh sso: unknown subject and JIT disabled", "subject", subject)
			return nil, proxy.ErrUnauthorized
		}
		u, err = b.st.JITCreateUser(ctx, subject)
		if err != nil {
			return nil, err
		}
		b.logger.Info("ssh sso: JIT-provisioned user (no grants)", "subject", subject, "user_id", u.ID)
	} else if err != nil {
		return nil, err
	}
	if u.Status != "active" {
		return nil, proxy.ErrUnauthorized
	}
	return &proxy.Identity{Subject: model.SubjectUser, ID: u.ID, Label: u.Username}, nil
}
