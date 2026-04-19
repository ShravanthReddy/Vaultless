// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Shravanth. All rights reserved.

package db

import (
	"database/sql"
	"testing"
	"time"
)

func TestSyncStateStore_Upsert_And_Get(t *testing.T) {
	database, ctx := setupTestDB(t)
	projectID := createTestProject(t, database, ctx)
	envID := createTestEnv(t, database, ctx, projectID, "dev")
	store := NewSyncStateStore(database)

	now := time.Now().UTC()
	state := &SyncState{
		ID:            "sync-1",
		EnvironmentID: envID,
		LastPushAt:    &now,
		RemoteHash:    "abc123",
		LocalHash:     "def456",
	}

	err := database.WithTx(ctx, func(tx *sql.Tx) error {
		return store.Upsert(ctx, tx, state)
	})
	if err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	loaded, err := store.Get(ctx, envID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if loaded == nil {
		t.Fatal("expected non-nil sync state")
	}
	if loaded.RemoteHash != "abc123" {
		t.Fatalf("expected 'abc123', got %q", loaded.RemoteHash)
	}
	if loaded.LocalHash != "def456" {
		t.Fatalf("expected 'def456', got %q", loaded.LocalHash)
	}
	if loaded.LastPushAt == nil {
		t.Fatal("expected LastPushAt to be set")
	}
	if loaded.LastPullAt != nil {
		t.Fatal("expected LastPullAt to be nil")
	}
}

func TestSyncStateStore_Get_NotFound(t *testing.T) {
	database, ctx := setupTestDB(t)
	store := NewSyncStateStore(database)

	state, err := store.Get(ctx, "nonexistent-env")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if state != nil {
		t.Fatal("expected nil for nonexistent env")
	}
}

func TestSyncStateStore_Upsert_Update(t *testing.T) {
	database, ctx := setupTestDB(t)
	projectID := createTestProject(t, database, ctx)
	envID := createTestEnv(t, database, ctx, projectID, "dev")
	store := NewSyncStateStore(database)

	state := &SyncState{
		ID: "sync-upd", EnvironmentID: envID,
		RemoteHash: "first", LocalHash: "first",
	}
	_ = database.WithTx(ctx, func(tx *sql.Tx) error {
		return store.Upsert(ctx, tx, state)
	})

	// Update
	now := time.Now().UTC()
	state.RemoteHash = "updated"
	state.LastPullAt = &now
	_ = database.WithTx(ctx, func(tx *sql.Tx) error {
		return store.Upsert(ctx, tx, state)
	})

	loaded, _ := store.Get(ctx, envID)
	if loaded.RemoteHash != "updated" {
		t.Fatalf("expected 'updated', got %q", loaded.RemoteHash)
	}
	if loaded.LastPullAt == nil {
		t.Fatal("expected LastPullAt to be set after update")
	}
}
