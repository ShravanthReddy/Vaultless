// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Shravanth. All rights reserved.

package db

import (
	"context"
	"database/sql"
	"time"

	"github.com/vaultless/vaultless/internal/models"
)

// TokenStore handles token storage and retrieval.
type TokenStore struct {
	db *DB
}

func NewTokenStore(db *DB) *TokenStore {
	return &TokenStore{db: db}
}

func (s *TokenStore) Create(ctx context.Context, tx *sql.Tx, token *models.Token) error {
	now := time.Now().UTC().Format(time.RFC3339)
	var expiresAt *string
	if token.ExpiresAt != nil {
		e := token.ExpiresAt.UTC().Format(time.RFC3339)
		expiresAt = &e
	}
	_, err := tx.ExecContext(ctx,
		`INSERT INTO tokens (id, name, hashed_key, permission, created_at, expires_at, created_by, is_revoked)
		VALUES (?, ?, ?, ?, ?, ?, ?, 0)`,
		token.ID, token.Name, token.HashedKey, token.Permission, now, expiresAt, token.CreatedBy,
	)
	return err
}

func (s *TokenStore) GetByHashedKey(ctx context.Context, hashedKey []byte) (*models.Token, error) {
	row := s.db.conn.QueryRowContext(ctx,
		`SELECT id, name, hashed_key, permission, created_at, expires_at, last_used_at, created_by, is_revoked
		FROM tokens WHERE hashed_key = ?`, hashedKey,
	)
	return scanToken(row)
}

func (s *TokenStore) GetByName(ctx context.Context, name string) (*models.Token, error) {
	row := s.db.conn.QueryRowContext(ctx,
		`SELECT id, name, hashed_key, permission, created_at, expires_at, last_used_at, created_by, is_revoked
		FROM tokens WHERE name = ?`, name,
	)
	return scanToken(row)
}

func (s *TokenStore) List(ctx context.Context) ([]models.Token, error) {
	rows, err := s.db.conn.QueryContext(ctx,
		`SELECT id, name, hashed_key, permission, created_at, expires_at, last_used_at, created_by, is_revoked
		FROM tokens ORDER BY created_at DESC`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tokens []models.Token
	for rows.Next() {
		var t models.Token
		var createdAt, createdBy string
		var expiresAt, lastUsedAt sql.NullString
		var isRevoked int
		if err := rows.Scan(&t.ID, &t.Name, &t.HashedKey, &t.Permission,
			&createdAt, &expiresAt, &lastUsedAt, &createdBy, &isRevoked); err != nil {
			return nil, err
		}
		t.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
		t.CreatedBy = createdBy
		t.IsRevoked = isRevoked != 0
		if expiresAt.Valid {
			ea, _ := time.Parse(time.RFC3339, expiresAt.String)
			t.ExpiresAt = &ea
		}
		if lastUsedAt.Valid {
			lu, _ := time.Parse(time.RFC3339, lastUsedAt.String)
			t.LastUsedAt = &lu
		}
		tokens = append(tokens, t)
	}
	return tokens, rows.Err()
}

func (s *TokenStore) Revoke(ctx context.Context, tx *sql.Tx, name string) error {
	_, err := tx.ExecContext(ctx,
		"UPDATE tokens SET is_revoked = 1 WHERE name = ?", name,
	)
	return err
}

func (s *TokenStore) UpdateLastUsed(ctx context.Context, tokenID string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := s.db.conn.ExecContext(ctx,
		"UPDATE tokens SET last_used_at = ? WHERE id = ?", now, tokenID,
	)
	return err
}

func scanToken(row *sql.Row) (*models.Token, error) {
	var t models.Token
	var createdAt, createdBy string
	var expiresAt, lastUsedAt sql.NullString
	var isRevoked int
	if err := row.Scan(&t.ID, &t.Name, &t.HashedKey, &t.Permission,
		&createdAt, &expiresAt, &lastUsedAt, &createdBy, &isRevoked); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	t.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	t.CreatedBy = createdBy
	t.IsRevoked = isRevoked != 0
	if expiresAt.Valid {
		ea, _ := time.Parse(time.RFC3339, expiresAt.String)
		t.ExpiresAt = &ea
	}
	if lastUsedAt.Valid {
		lu, _ := time.Parse(time.RFC3339, lastUsedAt.String)
		t.LastUsedAt = &lu
	}
	return &t, nil
}
