// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Shravanth. All rights reserved.

package db

import (
	"database/sql"
	"testing"

	"github.com/vaultless/vaultless/internal/models"
)

func TestProjectStore_Create_And_GetByID(t *testing.T) {
	database, ctx := setupTestDB(t)
	store := NewProjectStore(database)

	project := &models.Project{
		ID:   "proj-test-1",
		Name: "my-project",
	}

	err := database.WithTx(ctx, func(tx *sql.Tx) error {
		return store.Create(ctx, tx, project)
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	loaded, err := store.GetByID(ctx, "proj-test-1")
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if loaded == nil {
		t.Fatal("expected non-nil project")
	}
	if loaded.Name != "my-project" {
		t.Fatalf("expected 'my-project', got %q", loaded.Name)
	}
	if loaded.CreatedAt.IsZero() {
		t.Fatal("expected CreatedAt to be set")
	}
}

func TestProjectStore_GetByID_NotFound(t *testing.T) {
	database, ctx := setupTestDB(t)
	store := NewProjectStore(database)

	loaded, err := store.GetByID(ctx, "nonexistent")
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if loaded != nil {
		t.Fatal("expected nil for nonexistent project")
	}
}
