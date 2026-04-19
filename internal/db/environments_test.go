// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Shravanth. All rights reserved.

package db

import (
	"database/sql"
	"testing"

	"github.com/vaultless/vaultless/internal/models"
)

func TestEnvironmentStore_Create_And_GetByName(t *testing.T) {
	database, ctx := setupTestDB(t)
	projectID := createTestProject(t, database, ctx)
	store := NewEnvironmentStore(database)

	err := database.WithTx(ctx, func(tx *sql.Tx) error {
		return store.Create(ctx, tx, &models.Environment{
			ID: "env-1", ProjectID: projectID, Name: "production",
		})
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	env, err := store.GetByName(ctx, projectID, "production")
	if err != nil {
		t.Fatalf("GetByName: %v", err)
	}
	if env == nil {
		t.Fatal("expected non-nil environment")
	}
	if env.Name != "production" {
		t.Fatalf("expected 'production', got %q", env.Name)
	}
	if env.ProjectID != projectID {
		t.Fatalf("project ID mismatch")
	}
}

func TestEnvironmentStore_GetByName_NotFound(t *testing.T) {
	database, ctx := setupTestDB(t)
	store := NewEnvironmentStore(database)

	env, err := store.GetByName(ctx, "nonexistent", "dev")
	if err != nil {
		t.Fatalf("GetByName: %v", err)
	}
	if env != nil {
		t.Fatal("expected nil for nonexistent environment")
	}
}

func TestEnvironmentStore_List(t *testing.T) {
	database, ctx := setupTestDB(t)
	projectID := createTestProject(t, database, ctx)
	store := NewEnvironmentStore(database)

	for _, name := range []string{"staging", "production", "development"} {
		_ = database.WithTx(ctx, func(tx *sql.Tx) error {
			return store.Create(ctx, tx, &models.Environment{
				ID: "env-" + name, ProjectID: projectID, Name: name,
			})
		})
	}

	envs, err := store.List(ctx, projectID)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(envs) != 3 {
		t.Fatalf("expected 3 envs, got %d", len(envs))
	}
	// Sorted alphabetically
	if envs[0].Name != "development" {
		t.Fatalf("expected 'development' first, got %q", envs[0].Name)
	}
}

func TestEnvironmentStore_List_WithSecretCount(t *testing.T) {
	database, ctx := setupTestDB(t)
	projectID := createTestProject(t, database, ctx)
	envStore := NewEnvironmentStore(database)
	secStore := NewSecretStore(database)

	_ = database.WithTx(ctx, func(tx *sql.Tx) error {
		return envStore.Create(ctx, tx, &models.Environment{
			ID: "env-count", ProjectID: projectID, Name: "counted",
		})
	})

	// Add 2 secrets
	for _, name := range []string{"KEY_A", "KEY_B"} {
		_ = database.WithTx(ctx, func(tx *sql.Tx) error {
			return secStore.Upsert(ctx, tx, &models.Secret{
				ID: "s-" + name, EnvironmentID: "env-count", KeyName: name,
				EncryptedValue: []byte("d"), Nonce: []byte("nonce1234567"),
				Version: 1, CreatedBy: "test",
			})
		})
	}

	envs, _ := envStore.List(ctx, projectID)
	if len(envs) != 1 {
		t.Fatalf("expected 1 env, got %d", len(envs))
	}
	if envs[0].SecretCount != 2 {
		t.Fatalf("expected SecretCount 2, got %d", envs[0].SecretCount)
	}
}

func TestEnvironmentStore_Delete_Cascades(t *testing.T) {
	database, ctx := setupTestDB(t)
	projectID := createTestProject(t, database, ctx)
	envStore := NewEnvironmentStore(database)
	secStore := NewSecretStore(database)

	_ = database.WithTx(ctx, func(tx *sql.Tx) error {
		return envStore.Create(ctx, tx, &models.Environment{
			ID: "env-cascade", ProjectID: projectID, Name: "ephemeral",
		})
	})

	_ = database.WithTx(ctx, func(tx *sql.Tx) error {
		return secStore.Upsert(ctx, tx, &models.Secret{
			ID: "s-casc", EnvironmentID: "env-cascade", KeyName: "KEY",
			EncryptedValue: []byte("d"), Nonce: []byte("nonce1234567"),
			Version: 1, CreatedBy: "test",
		})
	})

	err := database.WithTx(ctx, func(tx *sql.Tx) error {
		return envStore.Delete(ctx, tx, "env-cascade")
	})
	if err != nil {
		t.Fatalf("Delete: %v", err)
	}

	// Environment should be gone
	env, _ := envStore.GetByName(ctx, projectID, "ephemeral")
	if env != nil {
		t.Fatal("expected environment to be deleted")
	}

	// Secrets should be gone
	keys, _ := secStore.ListKeys(ctx, "env-cascade")
	if len(keys) != 0 {
		t.Fatalf("expected 0 secrets after cascade delete, got %d", len(keys))
	}
}

func TestEnvironmentStore_ListNames(t *testing.T) {
	database, ctx := setupTestDB(t)
	projectID := createTestProject(t, database, ctx)
	store := NewEnvironmentStore(database)

	for _, name := range []string{"beta", "alpha"} {
		_ = database.WithTx(ctx, func(tx *sql.Tx) error {
			return store.Create(ctx, tx, &models.Environment{
				ID: "env-" + name, ProjectID: projectID, Name: name,
			})
		})
	}

	names, err := store.ListNames(ctx, projectID)
	if err != nil {
		t.Fatalf("ListNames: %v", err)
	}
	if len(names) != 2 {
		t.Fatalf("expected 2 names, got %d", len(names))
	}
	if names[0] != "alpha" {
		t.Fatalf("expected sorted, got %q first", names[0])
	}
}

func TestEnvironmentStore_Create_Duplicate(t *testing.T) {
	database, ctx := setupTestDB(t)
	projectID := createTestProject(t, database, ctx)
	store := NewEnvironmentStore(database)

	_ = database.WithTx(ctx, func(tx *sql.Tx) error {
		return store.Create(ctx, tx, &models.Environment{
			ID: "env-dup1", ProjectID: projectID, Name: "duplicate",
		})
	})

	err := database.WithTx(ctx, func(tx *sql.Tx) error {
		return store.Create(ctx, tx, &models.Environment{
			ID: "env-dup2", ProjectID: projectID, Name: "duplicate",
		})
	})
	if err == nil {
		t.Fatal("expected error for duplicate environment name")
	}
}
