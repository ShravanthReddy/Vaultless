// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Shravanth. All rights reserved.

package service

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/vaultless/vaultless/internal/crypto"
	"github.com/vaultless/vaultless/internal/db"
	"github.com/vaultless/vaultless/internal/models"
)

// mockBackend implements syncpkg.SyncBackend for testing.
type mockBackend struct {
	hash string
}

func (m *mockBackend) Push(data []byte) error  { return nil }
func (m *mockBackend) Pull() ([]byte, error)   { return nil, nil }
func (m *mockBackend) Hash() (string, error)   { return m.hash, nil }

func testSyncSetup(t *testing.T) (*SyncService, *mockBackend, context.Context) {
	t.Helper()
	tmpDir := t.TempDir()
	database, err := db.Open(filepath.Join(tmpDir, "test.db"))
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { database.Close() })

	ctx := context.Background()
	projectID := crypto.GenerateUUID()

	// Create project and environment
	err = database.WithTx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx,
			"INSERT INTO projects (id, name, created_at, updated_at) VALUES (?, 'test', ?, ?)",
			projectID, time.Now().UTC().Format(time.RFC3339), time.Now().UTC().Format(time.RFC3339))
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx,
			"INSERT INTO environments (id, project_id, name, created_at, updated_at) VALUES (?, ?, 'dev', ?, ?)",
			crypto.GenerateUUID(), projectID, time.Now().UTC().Format(time.RFC3339), time.Now().UTC().Format(time.RFC3339))
		return err
	})
	if err != nil {
		t.Fatalf("setup: %v", err)
	}

	backend := &mockBackend{hash: "default-hash"}
	svc := NewSyncService(database, nil, backend, projectID)
	return svc, backend, ctx
}

func TestSyncService_Push_FirstPush(t *testing.T) {
	svc, backend, ctx := testSyncSetup(t)
	backend.hash = "hash-abc123"

	err := svc.Push(ctx, "dev", false)
	if err != nil {
		t.Fatalf("Push: %v", err)
	}

	state, err := svc.GetState(ctx, "dev")
	if err != nil {
		t.Fatalf("GetState: %v", err)
	}
	if state == nil {
		t.Fatal("expected sync state after push")
	}
	if state.LocalHash != "hash-abc123" {
		t.Fatalf("expected local hash 'hash-abc123', got %q", state.LocalHash)
	}
	if state.RemoteHash != "hash-abc123" {
		t.Fatalf("expected remote hash 'hash-abc123', got %q", state.RemoteHash)
	}
	if state.LastPushAt == nil {
		t.Fatal("expected LastPushAt to be set")
	}
}

func TestSyncService_Pull_FirstPull(t *testing.T) {
	svc, backend, ctx := testSyncSetup(t)
	backend.hash = "hash-remote1"

	err := svc.Pull(ctx, "dev", false)
	if err != nil {
		t.Fatalf("Pull: %v", err)
	}

	state, err := svc.GetState(ctx, "dev")
	if err != nil {
		t.Fatalf("GetState: %v", err)
	}
	if state == nil {
		t.Fatal("expected sync state after pull")
	}
	if state.LocalHash != "hash-remote1" {
		t.Fatalf("expected local hash 'hash-remote1', got %q", state.LocalHash)
	}
	if state.LastPullAt == nil {
		t.Fatal("expected LastPullAt to be set")
	}
}

func TestSyncService_Pull_ConflictDetected(t *testing.T) {
	svc, backend, ctx := testSyncSetup(t)

	// Push first to establish state
	backend.hash = "hash-local1"
	if err := svc.Push(ctx, "dev", false); err != nil {
		t.Fatalf("Push: %v", err)
	}

	// Simulate remote divergence by updating remote_hash directly
	state, _ := svc.GetState(ctx, "dev")
	state.RemoteHash = "hash-remote-diverged"
	state.LocalHash = "hash-local1"
	err := svc.database.WithTx(ctx, func(tx *sql.Tx) error {
		return svc.syncState.Upsert(ctx, tx, state)
	})
	if err != nil {
		t.Fatalf("manual update: %v", err)
	}

	// Pull without force should detect conflict
	backend.hash = "hash-new-remote"
	err = svc.Pull(ctx, "dev", false)
	if err == nil {
		t.Fatal("expected conflict error")
	}

	var conflictErr *models.ErrConflict
	if !errors.As(err, &conflictErr) {
		t.Fatalf("expected ErrConflict, got %T: %v", err, err)
	}
	if conflictErr.LocalHash != "hash-local1" {
		t.Fatalf("expected local hash in error, got %q", conflictErr.LocalHash)
	}
}

func TestSyncService_Pull_ConflictForceOverride(t *testing.T) {
	svc, backend, ctx := testSyncSetup(t)

	// Setup conflicting state
	backend.hash = "hash-local1"
	if err := svc.Push(ctx, "dev", false); err != nil {
		t.Fatalf("Push: %v", err)
	}
	state, _ := svc.GetState(ctx, "dev")
	state.RemoteHash = "hash-remote-diverged"
	state.LocalHash = "hash-local1"
	_ = svc.database.WithTx(ctx, func(tx *sql.Tx) error {
		return svc.syncState.Upsert(ctx, tx, state)
	})

	// Pull with force should succeed
	backend.hash = "hash-forced"
	err := svc.Pull(ctx, "dev", true)
	if err != nil {
		t.Fatalf("Pull with force: %v", err)
	}

	newState, _ := svc.GetState(ctx, "dev")
	if newState.LocalHash != "hash-forced" {
		t.Fatalf("expected forced local hash, got %q", newState.LocalHash)
	}
}

func TestSyncService_Push_ConflictDetected(t *testing.T) {
	svc, backend, ctx := testSyncSetup(t)

	// Setup conflicting state
	backend.hash = "hash-initial"
	if err := svc.Push(ctx, "dev", false); err != nil {
		t.Fatalf("Push: %v", err)
	}
	state, _ := svc.GetState(ctx, "dev")
	state.RemoteHash = "hash-remote-changed"
	state.LocalHash = "hash-initial"
	_ = svc.database.WithTx(ctx, func(tx *sql.Tx) error {
		return svc.syncState.Upsert(ctx, tx, state)
	})

	// Push without force should detect conflict
	backend.hash = "hash-new-local"
	err := svc.Push(ctx, "dev", false)
	if err == nil {
		t.Fatal("expected conflict error")
	}
	var conflictErr *models.ErrConflict
	if !errors.As(err, &conflictErr) {
		t.Fatalf("expected ErrConflict, got %T: %v", err, err)
	}
}

func TestSyncService_Push_ConflictForceOverride(t *testing.T) {
	svc, backend, ctx := testSyncSetup(t)

	// Setup conflicting state
	backend.hash = "hash-initial"
	if err := svc.Push(ctx, "dev", false); err != nil {
		t.Fatalf("Push: %v", err)
	}
	state, _ := svc.GetState(ctx, "dev")
	state.RemoteHash = "hash-remote-changed"
	state.LocalHash = "hash-initial"
	_ = svc.database.WithTx(ctx, func(tx *sql.Tx) error {
		return svc.syncState.Upsert(ctx, tx, state)
	})

	// Push with force should succeed
	backend.hash = "hash-forced"
	err := svc.Push(ctx, "dev", true)
	if err != nil {
		t.Fatalf("Push with force: %v", err)
	}
}

func TestSyncService_NonexistentEnv(t *testing.T) {
	svc, _, ctx := testSyncSetup(t)

	err := svc.Pull(ctx, "nonexistent", false)
	if err == nil {
		t.Fatal("expected error for nonexistent env")
	}
	var notFound *models.ErrNotFound
	if !errors.As(err, &notFound) {
		t.Fatalf("expected ErrNotFound, got %T: %v", err, err)
	}
}
