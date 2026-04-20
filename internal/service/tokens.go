// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Shravanth. All rights reserved.

package service

import (
	"context"
	"database/sql"
	"time"

	"github.com/vaultless/vaultless/internal/crypto"
	"github.com/vaultless/vaultless/internal/db"
	"github.com/vaultless/vaultless/internal/models"
)

// TokenCreateResult holds the result of creating a token.
type TokenCreateResult struct {
	ID         string
	Name       string
	Key        string // plaintext key, shown once
	Permission string
	ExpiresAt  *time.Time
	CreatedBy  string
}

// TokensService handles token CRUD operations.
type TokensService struct {
	database *db.DB
	tokens   *db.TokenStore
	identity string
}

func NewTokensService(database *db.DB, identity string) *TokensService {
	return &TokensService{
		database: database,
		tokens:   db.NewTokenStore(database),
		identity: identity,
	}
}

// Create creates a new API token.
func (s *TokensService) Create(ctx context.Context, name, permission string, ttl time.Duration) (*TokenCreateResult, error) {
	// Check for duplicate
	existing, err := s.tokens.GetByName(ctx, name)
	if err != nil {
		return nil, err
	}
	if existing != nil {
		return nil, &models.ErrAlreadyExists{Entity: "token", Name: name}
	}

	plainKey := crypto.GenerateTokenKey()
	hashedKey := crypto.HashSHA256([]byte(plainKey))

	token := &models.Token{
		ID:        crypto.GenerateUUID(),
		Name:      name,
		HashedKey: hashedKey,
		Permission: permission,
		CreatedBy: s.identity,
	}

	if ttl > 0 {
		exp := time.Now().UTC().Add(ttl)
		token.ExpiresAt = &exp
	}

	err = s.database.WithTx(ctx, func(tx *sql.Tx) error {
		return s.tokens.Create(ctx, tx, token)
	})
	if err != nil {
		return nil, err
	}

	return &TokenCreateResult{
		ID:         token.ID,
		Name:       name,
		Key:        plainKey,
		Permission: permission,
		ExpiresAt:  token.ExpiresAt,
		CreatedBy:  s.identity,
	}, nil
}

// List returns all tokens.
func (s *TokensService) List(ctx context.Context) ([]models.Token, error) {
	return s.tokens.List(ctx)
}

// Revoke marks a token as revoked.
func (s *TokensService) Revoke(ctx context.Context, name string) error {
	existing, err := s.tokens.GetByName(ctx, name)
	if err != nil {
		return err
	}
	if existing == nil {
		return &models.ErrNotFound{Entity: "token", Name: name}
	}

	return s.database.WithTx(ctx, func(tx *sql.Tx) error {
		return s.tokens.Revoke(ctx, tx, name)
	})
}

// Validate checks if a token (by plaintext key) is valid.
// Returns the token if valid; returns an error if revoked, expired, or not found.
func (s *TokensService) Validate(ctx context.Context, plainKey string) (*models.Token, error) {
	hashedKey := crypto.HashSHA256([]byte(plainKey))
	token, err := s.tokens.GetByHashedKey(ctx, hashedKey)
	if err != nil {
		return nil, err
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

	// Update last used timestamp
	_ = s.tokens.UpdateLastUsed(ctx, token.ID)

	return token, nil
}
