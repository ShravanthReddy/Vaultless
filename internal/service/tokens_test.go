// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Shravanth. All rights reserved.

package service

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vaultless/vaultless/internal/db"
	"github.com/vaultless/vaultless/internal/models"
)

func testTokensSetup(t *testing.T) (*TokensService, context.Context) {
	t.Helper()
	tmpDir := t.TempDir()
	database, err := db.Open(filepath.Join(tmpDir, "test.db"))
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { database.Close() })

	svc := NewTokensService(database, "admin@example.com")
	return svc, context.Background()
}

func TestTokensService_Create(t *testing.T) {
	svc, ctx := testTokensSetup(t)

	result, err := svc.Create(ctx, "ci-token", "read-only", 24*time.Hour)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if result.Name != "ci-token" {
		t.Fatalf("expected name 'ci-token', got %q", result.Name)
	}
	if result.Permission != "read-only" {
		t.Fatalf("expected permission 'read-only', got %q", result.Permission)
	}
	if !strings.HasPrefix(result.Key, "vlt_") {
		t.Fatalf("expected key prefix 'vlt_', got %q", result.Key[:4])
	}
	if result.ExpiresAt == nil {
		t.Fatal("expected ExpiresAt to be set")
	}
	if result.CreatedBy != "admin@example.com" {
		t.Fatalf("expected CreatedBy 'admin@example.com', got %q", result.CreatedBy)
	}
	if result.ID == "" {
		t.Fatal("expected non-empty ID")
	}
}

func TestTokensService_Create_NoExpiry(t *testing.T) {
	svc, ctx := testTokensSetup(t)

	result, err := svc.Create(ctx, "permanent", "read-write", 0)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if result.ExpiresAt != nil {
		t.Fatal("expected nil ExpiresAt for no-expiry token")
	}
}

func TestTokensService_Create_Duplicate(t *testing.T) {
	svc, ctx := testTokensSetup(t)

	_, err := svc.Create(ctx, "dup-name", "read-only", 0)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	_, err = svc.Create(ctx, "dup-name", "read-write", 0)
	if err == nil {
		t.Fatal("expected error for duplicate token name")
	}
	var alreadyExists *models.ErrAlreadyExists
	if !errors.As(err, &alreadyExists) {
		t.Fatalf("expected ErrAlreadyExists, got %T: %v", err, err)
	}
}

func TestTokensService_List(t *testing.T) {
	svc, ctx := testTokensSetup(t)

	// Empty list initially
	tokens, err := svc.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(tokens) != 0 {
		t.Fatalf("expected 0 tokens, got %d", len(tokens))
	}

	_, _ = svc.Create(ctx, "token-a", "read-only", 0)
	_, _ = svc.Create(ctx, "token-b", "read-write", time.Hour)

	tokens, err = svc.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(tokens) != 2 {
		t.Fatalf("expected 2 tokens, got %d", len(tokens))
	}
}

func TestTokensService_Revoke(t *testing.T) {
	svc, ctx := testTokensSetup(t)

	_, err := svc.Create(ctx, "revoke-me", "read-only", 0)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	err = svc.Revoke(ctx, "revoke-me")
	if err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	// Token should still appear in list but be marked as revoked
	tokens, _ := svc.List(ctx)
	var found bool
	for _, tok := range tokens {
		if tok.Name == "revoke-me" {
			found = true
			if !tok.IsRevoked {
				t.Fatal("expected token to be revoked")
			}
		}
	}
	if !found {
		t.Fatal("revoked token not found in list")
	}
}

func TestTokensService_Revoke_NotFound(t *testing.T) {
	svc, ctx := testTokensSetup(t)

	err := svc.Revoke(ctx, "nonexistent")
	if err == nil {
		t.Fatal("expected error revoking nonexistent token")
	}
	var notFound *models.ErrNotFound
	if !errors.As(err, &notFound) {
		t.Fatalf("expected ErrNotFound, got %T: %v", err, err)
	}
}

func TestTokensService_Create_UniqueKeys(t *testing.T) {
	svc, ctx := testTokensSetup(t)

	r1, _ := svc.Create(ctx, "unique-a", "read-only", 0)
	r2, _ := svc.Create(ctx, "unique-b", "read-only", 0)

	if r1.Key == r2.Key {
		t.Fatal("two tokens should not have the same key")
	}
}

func TestTokensService_List_OrderByCreatedDesc(t *testing.T) {
	svc, ctx := testTokensSetup(t)

	_, _ = svc.Create(ctx, "first", "read-only", 0)
	time.Sleep(1100 * time.Millisecond) // ensure different created_at second
	_, _ = svc.Create(ctx, "second", "read-only", 0)

	tokens, _ := svc.List(ctx)
	// Ordered by created_at DESC
	if tokens[0].Name != "second" {
		t.Fatalf("expected most recent first, got %q", tokens[0].Name)
	}
}
