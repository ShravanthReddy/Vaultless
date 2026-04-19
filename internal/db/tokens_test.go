// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Shravanth. All rights reserved.

package db

import (
	"database/sql"
	"testing"
	"time"

	"github.com/vaultless/vaultless/internal/models"
)

func TestTokenStore_Create_And_GetByName(t *testing.T) {
	database, ctx := setupTestDB(t)
	store := NewTokenStore(database)

	token := &models.Token{
		ID:         "tok-1",
		Name:       "ci-deploy",
		HashedKey:  []byte("hashed-key-bytes"),
		Permission: "read-only",
		CreatedBy:  "admin@example.com",
	}

	err := database.WithTx(ctx, func(tx *sql.Tx) error {
		return store.Create(ctx, tx, token)
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	loaded, err := store.GetByName(ctx, "ci-deploy")
	if err != nil {
		t.Fatalf("GetByName: %v", err)
	}
	if loaded == nil {
		t.Fatal("expected non-nil token")
	}
	if loaded.Name != "ci-deploy" {
		t.Fatalf("expected 'ci-deploy', got %q", loaded.Name)
	}
	if loaded.Permission != "read-only" {
		t.Fatalf("expected 'read-only', got %q", loaded.Permission)
	}
	if loaded.IsRevoked {
		t.Fatal("expected not revoked")
	}
}

func TestTokenStore_Create_WithExpiry(t *testing.T) {
	database, ctx := setupTestDB(t)
	store := NewTokenStore(database)

	expiry := time.Now().Add(24 * time.Hour)
	token := &models.Token{
		ID: "tok-exp", Name: "expiring", HashedKey: []byte("hash"),
		Permission: "read-write", CreatedBy: "admin", ExpiresAt: &expiry,
	}

	_ = database.WithTx(ctx, func(tx *sql.Tx) error {
		return store.Create(ctx, tx, token)
	})

	loaded, _ := store.GetByName(ctx, "expiring")
	if loaded.ExpiresAt == nil {
		t.Fatal("expected ExpiresAt to be set")
	}
}

func TestTokenStore_GetByHashedKey(t *testing.T) {
	database, ctx := setupTestDB(t)
	store := NewTokenStore(database)

	hashedKey := []byte("unique-hash-for-lookup")
	token := &models.Token{
		ID: "tok-hash", Name: "hash-lookup", HashedKey: hashedKey,
		Permission: "read-only", CreatedBy: "admin",
	}
	_ = database.WithTx(ctx, func(tx *sql.Tx) error {
		return store.Create(ctx, tx, token)
	})

	loaded, err := store.GetByHashedKey(ctx, hashedKey)
	if err != nil {
		t.Fatalf("GetByHashedKey: %v", err)
	}
	if loaded == nil {
		t.Fatal("expected non-nil token")
	}
	if loaded.Name != "hash-lookup" {
		t.Fatalf("expected 'hash-lookup', got %q", loaded.Name)
	}
}

func TestTokenStore_GetByHashedKey_NotFound(t *testing.T) {
	database, ctx := setupTestDB(t)
	store := NewTokenStore(database)

	loaded, err := store.GetByHashedKey(ctx, []byte("nonexistent"))
	if err != nil {
		t.Fatalf("GetByHashedKey: %v", err)
	}
	if loaded != nil {
		t.Fatal("expected nil for nonexistent hashed key")
	}
}

func TestTokenStore_List(t *testing.T) {
	database, ctx := setupTestDB(t)
	store := NewTokenStore(database)

	for _, name := range []string{"first", "second"} {
		_ = database.WithTx(ctx, func(tx *sql.Tx) error {
			return store.Create(ctx, tx, &models.Token{
				ID: "tok-" + name, Name: name, HashedKey: []byte("h-" + name),
				Permission: "read-only", CreatedBy: "admin",
			})
		})
	}

	tokens, err := store.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(tokens) != 2 {
		t.Fatalf("expected 2, got %d", len(tokens))
	}
}

func TestTokenStore_Revoke(t *testing.T) {
	database, ctx := setupTestDB(t)
	store := NewTokenStore(database)

	_ = database.WithTx(ctx, func(tx *sql.Tx) error {
		return store.Create(ctx, tx, &models.Token{
			ID: "tok-rev", Name: "revoke-me", HashedKey: []byte("h"),
			Permission: "read-only", CreatedBy: "admin",
		})
	})

	err := database.WithTx(ctx, func(tx *sql.Tx) error {
		return store.Revoke(ctx, tx, "revoke-me")
	})
	if err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	loaded, _ := store.GetByName(ctx, "revoke-me")
	if !loaded.IsRevoked {
		t.Fatal("expected token to be revoked")
	}
}

func TestTokenStore_UpdateLastUsed(t *testing.T) {
	database, ctx := setupTestDB(t)
	store := NewTokenStore(database)

	_ = database.WithTx(ctx, func(tx *sql.Tx) error {
		return store.Create(ctx, tx, &models.Token{
			ID: "tok-lu", Name: "last-used", HashedKey: []byte("h"),
			Permission: "read-only", CreatedBy: "admin",
		})
	})

	err := store.UpdateLastUsed(ctx, "tok-lu")
	if err != nil {
		t.Fatalf("UpdateLastUsed: %v", err)
	}

	loaded, _ := store.GetByName(ctx, "last-used")
	if loaded.LastUsedAt == nil {
		t.Fatal("expected LastUsedAt to be set")
	}
}

func TestTokenStore_GetByName_NotFound(t *testing.T) {
	database, ctx := setupTestDB(t)
	store := NewTokenStore(database)

	loaded, err := store.GetByName(ctx, "nonexistent")
	if err != nil {
		t.Fatalf("GetByName: %v", err)
	}
	if loaded != nil {
		t.Fatal("expected nil for nonexistent token")
	}
}
