// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Shravanth. All rights reserved.

package db

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/vaultless/vaultless/internal/models"
)

func setupTestDB(t *testing.T) (*DB, context.Context) {
	t.Helper()
	database, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { database.Close() })
	return database, context.Background()
}

// createTestProject inserts a project and returns its ID.
func createTestProject(t *testing.T, database *DB, ctx context.Context) string {
	t.Helper()
	id := "proj-" + time.Now().Format("150405.000")
	err := database.WithTx(ctx, func(tx *sql.Tx) error {
		_, err := tx.Exec("INSERT INTO projects (id, name, created_at, updated_at) VALUES (?, 'test', datetime('now'), datetime('now'))", id)
		return err
	})
	if err != nil {
		t.Fatalf("create project: %v", err)
	}
	return id
}

// createTestEnv inserts an environment and returns its ID.
func createTestEnv(t *testing.T, database *DB, ctx context.Context, projectID, name string) string {
	t.Helper()
	id := "env-" + name + "-" + time.Now().Format("150405.000")
	err := database.WithTx(ctx, func(tx *sql.Tx) error {
		_, err := tx.Exec("INSERT INTO environments (id, project_id, name, created_at, updated_at) VALUES (?, ?, ?, datetime('now'), datetime('now'))", id, projectID, name)
		return err
	})
	if err != nil {
		t.Fatalf("create env: %v", err)
	}
	return id
}

func TestSecretStore_Upsert_And_GetByKey(t *testing.T) {
	database, ctx := setupTestDB(t)
	projectID := createTestProject(t, database, ctx)
	envID := createTestEnv(t, database, ctx, projectID, "dev")

	store := NewSecretStore(database)
	secret := &models.Secret{
		ID:             "sec-1",
		EnvironmentID:  envID,
		KeyName:        "API_KEY",
		EncryptedValue: []byte("encrypted-data"),
		Nonce:          []byte("nonce-12bytes"),
		Version:        1,
		CreatedBy:      "test@example.com",
	}

	err := database.WithTx(ctx, func(tx *sql.Tx) error {
		return store.Upsert(ctx, tx, secret)
	})
	if err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	loaded, err := store.GetByKey(ctx, envID, "API_KEY")
	if err != nil {
		t.Fatalf("GetByKey: %v", err)
	}
	if loaded == nil {
		t.Fatal("expected non-nil secret")
	}
	if loaded.KeyName != "API_KEY" {
		t.Fatalf("expected 'API_KEY', got %q", loaded.KeyName)
	}
	if string(loaded.EncryptedValue) != "encrypted-data" {
		t.Fatalf("unexpected encrypted value: %q", loaded.EncryptedValue)
	}
	if loaded.Version != 1 {
		t.Fatalf("expected version 1, got %d", loaded.Version)
	}
}

func TestSecretStore_Upsert_Update(t *testing.T) {
	database, ctx := setupTestDB(t)
	projectID := createTestProject(t, database, ctx)
	envID := createTestEnv(t, database, ctx, projectID, "dev")
	store := NewSecretStore(database)

	secret := &models.Secret{
		ID: "sec-upd", EnvironmentID: envID, KeyName: "KEY",
		EncryptedValue: []byte("v1"), Nonce: []byte("nonce1234567"),
		Version: 1, CreatedBy: "test",
	}
	_ = database.WithTx(ctx, func(tx *sql.Tx) error { return store.Upsert(ctx, tx, secret) })

	// Update
	secret.EncryptedValue = []byte("v2")
	secret.Version = 2
	_ = database.WithTx(ctx, func(tx *sql.Tx) error { return store.Upsert(ctx, tx, secret) })

	loaded, _ := store.GetByKey(ctx, envID, "KEY")
	if loaded.Version != 2 {
		t.Fatalf("expected version 2, got %d", loaded.Version)
	}
	if string(loaded.EncryptedValue) != "v2" {
		t.Fatalf("expected 'v2', got %q", loaded.EncryptedValue)
	}
}

func TestSecretStore_GetByKey_NotFound(t *testing.T) {
	database, ctx := setupTestDB(t)
	store := NewSecretStore(database)

	result, err := store.GetByKey(ctx, "nonexistent-env", "KEY")
	if err != nil {
		t.Fatalf("GetByKey: %v", err)
	}
	if result != nil {
		t.Fatal("expected nil for nonexistent key")
	}
}

func TestSecretStore_SoftDelete(t *testing.T) {
	database, ctx := setupTestDB(t)
	projectID := createTestProject(t, database, ctx)
	envID := createTestEnv(t, database, ctx, projectID, "dev")
	store := NewSecretStore(database)

	secret := &models.Secret{
		ID: "sec-del", EnvironmentID: envID, KeyName: "DELETE_ME",
		EncryptedValue: []byte("data"), Nonce: []byte("nonce1234567"),
		Version: 1, CreatedBy: "test",
	}
	_ = database.WithTx(ctx, func(tx *sql.Tx) error { return store.Upsert(ctx, tx, secret) })

	err := database.WithTx(ctx, func(tx *sql.Tx) error {
		return store.SoftDelete(ctx, tx, envID, "DELETE_ME")
	})
	if err != nil {
		t.Fatalf("SoftDelete: %v", err)
	}

	loaded, _ := store.GetByKey(ctx, envID, "DELETE_ME")
	if loaded == nil {
		t.Fatal("soft-deleted secret should still exist in DB")
	}
	if !loaded.IsDeleted {
		t.Fatal("expected IsDeleted = true")
	}
}

func TestSecretStore_Purge(t *testing.T) {
	database, ctx := setupTestDB(t)
	projectID := createTestProject(t, database, ctx)
	envID := createTestEnv(t, database, ctx, projectID, "dev")
	store := NewSecretStore(database)
	versionStore := NewSecretVersionStore(database)

	secret := &models.Secret{
		ID: "sec-purge", EnvironmentID: envID, KeyName: "PURGE_ME",
		EncryptedValue: []byte("data"), Nonce: []byte("nonce1234567"),
		Version: 1, CreatedBy: "test",
	}
	_ = database.WithTx(ctx, func(tx *sql.Tx) error {
		if err := store.Upsert(ctx, tx, secret); err != nil {
			return err
		}
		return versionStore.Create(ctx, tx, &models.SecretVersion{
			ID: "ver-1", SecretID: "sec-purge", Version: 1,
			EncryptedValue: []byte("data"), Nonce: []byte("nonce1234567"),
			CreatedBy: "test", ChangeType: "created",
		})
	})

	err := database.WithTx(ctx, func(tx *sql.Tx) error {
		return store.Purge(ctx, tx, envID, "PURGE_ME")
	})
	if err != nil {
		t.Fatalf("Purge: %v", err)
	}

	loaded, _ := store.GetByKey(ctx, envID, "PURGE_ME")
	if loaded != nil {
		t.Fatal("purged secret should be completely removed")
	}

	versions, _ := versionStore.ListBySecretID(ctx, "sec-purge")
	if len(versions) != 0 {
		t.Fatalf("expected 0 versions after purge, got %d", len(versions))
	}
}

func TestSecretStore_List(t *testing.T) {
	database, ctx := setupTestDB(t)
	projectID := createTestProject(t, database, ctx)
	envID := createTestEnv(t, database, ctx, projectID, "dev")
	store := NewSecretStore(database)

	for _, name := range []string{"BETA", "ALPHA", "GAMMA"} {
		_ = database.WithTx(ctx, func(tx *sql.Tx) error {
			return store.Upsert(ctx, tx, &models.Secret{
				ID: "s-" + name, EnvironmentID: envID, KeyName: name,
				EncryptedValue: []byte("d"), Nonce: []byte("nonce1234567"),
				Version: 1, CreatedBy: "test",
			})
		})
	}

	entries, err := store.List(ctx, envID)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("expected 3, got %d", len(entries))
	}
	if entries[0].KeyName != "ALPHA" {
		t.Fatalf("expected sorted, first is %q", entries[0].KeyName)
	}
}

func TestSecretStore_List_ExcludesDeleted(t *testing.T) {
	database, ctx := setupTestDB(t)
	projectID := createTestProject(t, database, ctx)
	envID := createTestEnv(t, database, ctx, projectID, "dev")
	store := NewSecretStore(database)

	_ = database.WithTx(ctx, func(tx *sql.Tx) error {
		return store.Upsert(ctx, tx, &models.Secret{
			ID: "s-vis", EnvironmentID: envID, KeyName: "VISIBLE",
			EncryptedValue: []byte("d"), Nonce: []byte("nonce1234567"),
			Version: 1, CreatedBy: "test",
		})
	})
	_ = database.WithTx(ctx, func(tx *sql.Tx) error {
		store.Upsert(ctx, tx, &models.Secret{
			ID: "s-del", EnvironmentID: envID, KeyName: "DELETED",
			EncryptedValue: []byte("d"), Nonce: []byte("nonce1234567"),
			Version: 1, CreatedBy: "test", IsDeleted: true,
		})
		return nil
	})

	entries, _ := store.List(ctx, envID)
	if len(entries) != 1 {
		t.Fatalf("expected 1 (excluding deleted), got %d", len(entries))
	}
}

func TestSecretStore_ListKeys(t *testing.T) {
	database, ctx := setupTestDB(t)
	projectID := createTestProject(t, database, ctx)
	envID := createTestEnv(t, database, ctx, projectID, "dev")
	store := NewSecretStore(database)

	for _, name := range []string{"Z_KEY", "A_KEY"} {
		_ = database.WithTx(ctx, func(tx *sql.Tx) error {
			return store.Upsert(ctx, tx, &models.Secret{
				ID: "s-" + name, EnvironmentID: envID, KeyName: name,
				EncryptedValue: []byte("d"), Nonce: []byte("nonce1234567"),
				Version: 1, CreatedBy: "test",
			})
		})
	}

	keys, err := store.ListKeys(ctx, envID)
	if err != nil {
		t.Fatalf("ListKeys: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("expected 2 keys, got %d", len(keys))
	}
	if keys[0] != "A_KEY" {
		t.Fatalf("expected sorted, got %q first", keys[0])
	}
}

func TestSecretStore_CopyAll(t *testing.T) {
	database, ctx := setupTestDB(t)
	projectID := createTestProject(t, database, ctx)
	srcEnvID := createTestEnv(t, database, ctx, projectID, "source")
	dstEnvID := createTestEnv(t, database, ctx, projectID, "target")
	store := NewSecretStore(database)

	for _, name := range []string{"KEY_A", "KEY_B"} {
		_ = database.WithTx(ctx, func(tx *sql.Tx) error {
			return store.Upsert(ctx, tx, &models.Secret{
				ID: "src-" + name, EnvironmentID: srcEnvID, KeyName: name,
				EncryptedValue: []byte("data-" + name), Nonce: []byte("nonce1234567"),
				Version: 1, CreatedBy: "test",
			})
		})
	}

	counter := 0
	err := database.WithTx(ctx, func(tx *sql.Tx) error {
		return store.CopyAll(ctx, tx, srcEnvID, dstEnvID, func() string {
			counter++
			return "copied-" + string(rune('0'+counter))
		})
	})
	if err != nil {
		t.Fatalf("CopyAll: %v", err)
	}

	dstKeys, _ := store.ListKeys(ctx, dstEnvID)
	if len(dstKeys) != 2 {
		t.Fatalf("expected 2 keys in target, got %d", len(dstKeys))
	}
}

func TestSecretVersionStore_CreateAndList(t *testing.T) {
	database, ctx := setupTestDB(t)
	store := NewSecretVersionStore(database)
	projectID := createTestProject(t, database, ctx)
	envID := createTestEnv(t, database, ctx, projectID, "dev")
	secretStore := NewSecretStore(database)

	_ = database.WithTx(ctx, func(tx *sql.Tx) error {
		return secretStore.Upsert(ctx, tx, &models.Secret{
			ID: "sec-ver", EnvironmentID: envID, KeyName: "KEY",
			EncryptedValue: []byte("d"), Nonce: []byte("nonce1234567"),
			Version: 1, CreatedBy: "test",
		})
	})

	for i := 1; i <= 3; i++ {
		_ = database.WithTx(ctx, func(tx *sql.Tx) error {
			return store.Create(ctx, tx, &models.SecretVersion{
				ID: "v-" + string(rune('0'+i)), SecretID: "sec-ver", Version: i,
				EncryptedValue: []byte("data"), Nonce: []byte("nonce1234567"),
				CreatedBy: "test", ChangeType: "updated",
			})
		})
	}

	versions, err := store.ListBySecretID(ctx, "sec-ver")
	if err != nil {
		t.Fatalf("ListBySecretID: %v", err)
	}
	if len(versions) != 3 {
		t.Fatalf("expected 3, got %d", len(versions))
	}
	// DESC order
	if versions[0].Version != 3 {
		t.Fatalf("expected version 3 first, got %d", versions[0].Version)
	}
}

func TestSecretVersionStore_GetByVersion(t *testing.T) {
	database, ctx := setupTestDB(t)
	store := NewSecretVersionStore(database)
	projectID := createTestProject(t, database, ctx)
	envID := createTestEnv(t, database, ctx, projectID, "dev")
	secretStore := NewSecretStore(database)

	_ = database.WithTx(ctx, func(tx *sql.Tx) error {
		return secretStore.Upsert(ctx, tx, &models.Secret{
			ID: "sec-gv", EnvironmentID: envID, KeyName: "KEY",
			EncryptedValue: []byte("d"), Nonce: []byte("nonce1234567"),
			Version: 1, CreatedBy: "test",
		})
	})

	_ = database.WithTx(ctx, func(tx *sql.Tx) error {
		return store.Create(ctx, tx, &models.SecretVersion{
			ID: "v-1", SecretID: "sec-gv", Version: 1,
			EncryptedValue: []byte("ver1-data"), Nonce: []byte("nonce1234567"),
			CreatedBy: "test", ChangeType: "created",
		})
	})

	ver, err := store.GetByVersion(ctx, "sec-gv", 1)
	if err != nil {
		t.Fatalf("GetByVersion: %v", err)
	}
	if ver == nil {
		t.Fatal("expected non-nil version")
	}
	if string(ver.EncryptedValue) != "ver1-data" {
		t.Fatalf("expected 'ver1-data', got %q", ver.EncryptedValue)
	}

	// Nonexistent version
	ver, err = store.GetByVersion(ctx, "sec-gv", 99)
	if err != nil {
		t.Fatalf("GetByVersion 99: %v", err)
	}
	if ver != nil {
		t.Fatal("expected nil for nonexistent version")
	}
}

func TestSecretVersionStore_PruneOldVersions(t *testing.T) {
	database, ctx := setupTestDB(t)
	store := NewSecretVersionStore(database)
	projectID := createTestProject(t, database, ctx)
	envID := createTestEnv(t, database, ctx, projectID, "dev")
	secretStore := NewSecretStore(database)

	_ = database.WithTx(ctx, func(tx *sql.Tx) error {
		return secretStore.Upsert(ctx, tx, &models.Secret{
			ID: "sec-prune", EnvironmentID: envID, KeyName: "KEY",
			EncryptedValue: []byte("d"), Nonce: []byte("nonce1234567"),
			Version: 1, CreatedBy: "test",
		})
	})

	for i := 1; i <= 5; i++ {
		_ = database.WithTx(ctx, func(tx *sql.Tx) error {
			return store.Create(ctx, tx, &models.SecretVersion{
				ID: "prune-" + string(rune('0'+i)), SecretID: "sec-prune", Version: i,
				EncryptedValue: []byte("d"), Nonce: []byte("nonce1234567"),
				CreatedBy: "test", ChangeType: "updated",
			})
		})
	}

	// Prune to keep only 2
	err := database.WithTx(ctx, func(tx *sql.Tx) error {
		return store.PruneOldVersions(ctx, tx, "sec-prune", 2)
	})
	if err != nil {
		t.Fatalf("PruneOldVersions: %v", err)
	}

	remaining, _ := store.ListBySecretID(ctx, "sec-prune")
	if len(remaining) != 2 {
		t.Fatalf("expected 2 remaining, got %d", len(remaining))
	}
	// Should keep the newest (4, 5)
	if remaining[0].Version != 5 || remaining[1].Version != 4 {
		t.Fatalf("expected versions 5,4 remaining, got %d,%d", remaining[0].Version, remaining[1].Version)
	}
}
