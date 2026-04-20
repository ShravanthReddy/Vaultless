// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Shravanth. All rights reserved.

package auth

import (
	"context"
	"os"
	"time"

	"github.com/vaultless/vaultless/internal/config"
	"github.com/vaultless/vaultless/internal/crypto"
	"github.com/vaultless/vaultless/internal/db"
	"github.com/vaultless/vaultless/internal/models"
)

// Identity represents the authenticated user.
type Identity struct {
	Name       string
	Email      string
	AuthMethod string // "password", "token"
	TokenID    string
	Permission string // "read-write" or "read-only"
}

// Authenticator defines the authentication contract.
type Authenticator interface {
	Authenticate(ctx context.Context) (*Identity, error)
	Type() string
}

// Resolve returns the appropriate authenticator based on context.
func Resolve(cfg *config.ResolvedConfig, database *db.DB) Authenticator {
	// 1. Check for VAULTLESS_TOKEN env var
	if token := os.Getenv("VAULTLESS_TOKEN"); token != "" {
		return &TokenAuth{
			token:    token,
			tokens:   db.NewTokenStore(database),
			database: database,
		}
	}

	// 2. Fall back to password-based auth
	return &PasswordAuth{
		cfg: cfg,
	}
}

// TokenAuth authenticates via VAULTLESS_TOKEN environment variable.
type TokenAuth struct {
	token    string
	tokens   *db.TokenStore
	database *db.DB
}

func (a *TokenAuth) Type() string { return "token" }

func (a *TokenAuth) Authenticate(ctx context.Context) (*Identity, error) {
	hashedKey := crypto.HashSHA256([]byte(a.token))
	token, err := a.tokens.GetByHashedKey(ctx, hashedKey)
	if err != nil {
		return nil, &models.ErrAuth{Msg: "invalid token"}
	}
	if token == nil {
		return nil, &models.ErrAuth{Msg: "token not found"}
	}
	if token.IsRevoked {
		return nil, &models.ErrAuth{Msg: "token has been revoked"}
	}
	if token.ExpiresAt != nil && token.ExpiresAt.Before(time.Now()) {
		return nil, &models.ErrAuth{Msg: "token has expired"}
	}

	// Update last used
	_ = a.tokens.UpdateLastUsed(ctx, token.ID)

	return &Identity{
		Name:       token.Name,
		AuthMethod: "token",
		TokenID:    token.ID,
		Permission: token.Permission,
	}, nil
}

// Validate checks if a token is valid (not revoked, not expired) and returns the identity.
// This is a standalone validation method that should be called before any token-authenticated operation.
func (a *TokenAuth) Validate(ctx context.Context) (*Identity, error) {
	return a.Authenticate(ctx)
}

// PasswordAuth authenticates via master password.
type PasswordAuth struct {
	cfg *config.ResolvedConfig
}

func (a *PasswordAuth) Type() string { return "password" }

func (a *PasswordAuth) Authenticate(ctx context.Context) (*Identity, error) {
	return &Identity{
		Name:       a.cfg.UserName,
		Email:      a.cfg.UserEmail,
		AuthMethod: "password",
		Permission: "read-write",
	}, nil
}
