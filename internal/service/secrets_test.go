// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Shravanth. All rights reserved.

package service

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"

	"github.com/vaultless/vaultless/internal/crypto"
	"github.com/vaultless/vaultless/internal/db"
	"github.com/vaultless/vaultless/internal/models"
)

// testSecretsSetup creates a DB, project, environment, and SecretsService for testing.
func testSecretsSetup(t *testing.T) (*SecretsService, *db.DB, context.Context) {
	t.Helper()
	tmpDir := t.TempDir()
	database, err := db.Open(filepath.Join(tmpDir, "test.db"))
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { database.Close() })

	ctx := context.Background()
	projectID := crypto.GenerateUUID()
	projectKey, err := crypto.GenerateProjectKey()
	if err != nil {
		t.Fatalf("GenerateProjectKey: %v", err)
	}

	// Create a project row
	err = database.WithTx(ctx, func(tx *sql.Tx) error {
		_, err := tx.Exec("INSERT INTO projects (id, name, created_at, updated_at) VALUES (?, 'test', datetime('now'), datetime('now'))", projectID)
		return err
	})
	if err != nil {
		t.Fatalf("insert project: %v", err)
	}

	svc := NewSecretsService(database, projectID, projectKey, 10, "tester@example.com")

	// Create a default environment
	envSvc := NewEnvironmentsService(database, projectID)
	if err := envSvc.Create(ctx, "development"); err != nil {
		t.Fatalf("create env: %v", err)
	}

	return svc, database, ctx
}

func TestSecretsService_SetAndGet(t *testing.T) {
	svc, _, ctx := testSecretsSetup(t)

	version, err := svc.Set(ctx, "development", "API_KEY", []byte("secret-value-123"), false)
	if err != nil {
		t.Fatalf("Set: %v", err)
	}
	if version != 1 {
		t.Fatalf("expected version 1, got %d", version)
	}

	result, err := svc.Get(ctx, "development", "API_KEY")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(result.Value) != "secret-value-123" {
		t.Fatalf("expected 'secret-value-123', got %q", result.Value)
	}
	if result.KeyName != "API_KEY" {
		t.Fatalf("expected key 'API_KEY', got %q", result.KeyName)
	}
	if result.Version != 1 {
		t.Fatalf("expected version 1, got %d", result.Version)
	}
}

func TestSecretsService_Set_DuplicateWithoutForce(t *testing.T) {
	svc, _, ctx := testSecretsSetup(t)

	_, err := svc.Set(ctx, "development", "DB_HOST", []byte("localhost"), false)
	if err != nil {
		t.Fatalf("Set: %v", err)
	}

	_, err = svc.Set(ctx, "development", "DB_HOST", []byte("newhost"), false)
	if err == nil {
		t.Fatal("expected error for duplicate set without force")
	}
	var alreadyExists *models.ErrAlreadyExists
	if !errors.As(err, &alreadyExists) {
		t.Fatalf("expected ErrAlreadyExists, got %T: %v", err, err)
	}
}

func TestSecretsService_Set_ForceUpdate(t *testing.T) {
	svc, _, ctx := testSecretsSetup(t)

	_, err := svc.Set(ctx, "development", "DB_HOST", []byte("localhost"), false)
	if err != nil {
		t.Fatalf("Set: %v", err)
	}

	version, err := svc.Set(ctx, "development", "DB_HOST", []byte("newhost"), true)
	if err != nil {
		t.Fatalf("Set with force: %v", err)
	}
	if version != 2 {
		t.Fatalf("expected version 2, got %d", version)
	}

	result, err := svc.Get(ctx, "development", "DB_HOST")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(result.Value) != "newhost" {
		t.Fatalf("expected 'newhost', got %q", result.Value)
	}
}

func TestSecretsService_Set_InvalidKeyName(t *testing.T) {
	svc, _, ctx := testSecretsSetup(t)

	tests := []struct {
		name string
		key  string
	}{
		{"lowercase", "api_key"},
		{"starts with number", "1KEY"},
		{"contains dash", "MY-KEY"},
		{"empty", ""},
		{"contains space", "MY KEY"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := svc.Set(ctx, "development", tt.key, []byte("val"), false)
			if err == nil {
				t.Fatalf("expected validation error for key %q", tt.key)
			}
			var valErr *models.ErrValidation
			if !errors.As(err, &valErr) {
				t.Fatalf("expected ErrValidation, got %T: %v", err, err)
			}
		})
	}
}

func TestSecretsService_Set_NonexistentEnv(t *testing.T) {
	svc, _, ctx := testSecretsSetup(t)

	_, err := svc.Set(ctx, "nonexistent", "KEY", []byte("val"), false)
	if err == nil {
		t.Fatal("expected error for nonexistent environment")
	}
	var notFound *models.ErrNotFound
	if !errors.As(err, &notFound) {
		t.Fatalf("expected ErrNotFound, got %T: %v", err, err)
	}
}

func TestSecretsService_Get_NotFound(t *testing.T) {
	svc, _, ctx := testSecretsSetup(t)

	_, err := svc.Get(ctx, "development", "NONEXISTENT")
	if err == nil {
		t.Fatal("expected error for missing secret")
	}
	var notFound *models.ErrNotFound
	if !errors.As(err, &notFound) {
		t.Fatalf("expected ErrNotFound, got %T: %v", err, err)
	}
}

func TestSecretsService_Delete_SoftDelete(t *testing.T) {
	svc, _, ctx := testSecretsSetup(t)

	_, err := svc.Set(ctx, "development", "TO_DELETE", []byte("val"), false)
	if err != nil {
		t.Fatalf("Set: %v", err)
	}

	err = svc.Delete(ctx, "development", "TO_DELETE", false)
	if err != nil {
		t.Fatalf("Delete: %v", err)
	}

	_, err = svc.Get(ctx, "development", "TO_DELETE")
	if err == nil {
		t.Fatal("expected error getting deleted secret")
	}
	var notFound *models.ErrNotFound
	if !errors.As(err, &notFound) {
		t.Fatalf("expected ErrNotFound, got %T: %v", err, err)
	}
}

func TestSecretsService_Delete_Purge(t *testing.T) {
	svc, _, ctx := testSecretsSetup(t)

	_, err := svc.Set(ctx, "development", "PURGE_ME", []byte("val"), false)
	if err != nil {
		t.Fatalf("Set: %v", err)
	}

	err = svc.Delete(ctx, "development", "PURGE_ME", true)
	if err != nil {
		t.Fatalf("Purge: %v", err)
	}

	// History should also be gone
	_, err = svc.History(ctx, "development", "PURGE_ME")
	if err == nil {
		t.Fatal("expected error for purged secret history")
	}
}

func TestSecretsService_Delete_NotFound(t *testing.T) {
	svc, _, ctx := testSecretsSetup(t)

	err := svc.Delete(ctx, "development", "NOPE", false)
	if err == nil {
		t.Fatal("expected error deleting nonexistent secret")
	}
}

func TestSecretsService_List(t *testing.T) {
	svc, _, ctx := testSecretsSetup(t)

	keys := []string{"ALPHA", "BETA", "GAMMA"}
	for _, k := range keys {
		if _, err := svc.Set(ctx, "development", k, []byte("val-"+k), false); err != nil {
			t.Fatalf("Set %s: %v", k, err)
		}
	}

	entries, err := svc.List(ctx, "development")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(entries))
	}

	// Should be sorted alphabetically
	if entries[0].KeyName != "ALPHA" || entries[1].KeyName != "BETA" || entries[2].KeyName != "GAMMA" {
		t.Fatalf("unexpected order: %v %v %v", entries[0].KeyName, entries[1].KeyName, entries[2].KeyName)
	}
}

func TestSecretsService_ListKeys(t *testing.T) {
	svc, _, ctx := testSecretsSetup(t)

	for _, k := range []string{"X_KEY", "A_KEY", "M_KEY"} {
		if _, err := svc.Set(ctx, "development", k, []byte("v"), false); err != nil {
			t.Fatalf("Set: %v", err)
		}
	}

	keys, err := svc.ListKeys(ctx, "development")
	if err != nil {
		t.Fatalf("ListKeys: %v", err)
	}
	if len(keys) != 3 {
		t.Fatalf("expected 3 keys, got %d", len(keys))
	}
	if keys[0] != "A_KEY" {
		t.Fatalf("expected first key 'A_KEY', got %q", keys[0])
	}
}

func TestSecretsService_ListDecrypted(t *testing.T) {
	svc, _, ctx := testSecretsSetup(t)

	_, err := svc.Set(ctx, "development", "SECRET_A", []byte("value-a"), false)
	if err != nil {
		t.Fatalf("Set: %v", err)
	}
	_, err = svc.Set(ctx, "development", "SECRET_B", []byte("value-b"), false)
	if err != nil {
		t.Fatalf("Set: %v", err)
	}

	decrypted, err := svc.ListDecrypted(ctx, "development")
	if err != nil {
		t.Fatalf("ListDecrypted: %v", err)
	}
	if len(decrypted) != 2 {
		t.Fatalf("expected 2, got %d", len(decrypted))
	}
	if string(decrypted["SECRET_A"]) != "value-a" {
		t.Fatalf("SECRET_A: got %q", decrypted["SECRET_A"])
	}
	if string(decrypted["SECRET_B"]) != "value-b" {
		t.Fatalf("SECRET_B: got %q", decrypted["SECRET_B"])
	}
}

func TestSecretsService_History(t *testing.T) {
	svc, _, ctx := testSecretsSetup(t)

	// Create and update a few times
	_, err := svc.Set(ctx, "development", "VERSIONED", []byte("v1"), false)
	if err != nil {
		t.Fatalf("Set v1: %v", err)
	}
	_, err = svc.Set(ctx, "development", "VERSIONED", []byte("v2"), true)
	if err != nil {
		t.Fatalf("Set v2: %v", err)
	}
	_, err = svc.Set(ctx, "development", "VERSIONED", []byte("v3"), true)
	if err != nil {
		t.Fatalf("Set v3: %v", err)
	}

	history, err := svc.History(ctx, "development", "VERSIONED")
	if err != nil {
		t.Fatalf("History: %v", err)
	}
	if len(history) != 3 {
		t.Fatalf("expected 3 versions, got %d", len(history))
	}
	// History is DESC by version
	if history[0].Version != 3 {
		t.Fatalf("expected newest version 3 first, got %d", history[0].Version)
	}
	if history[0].ChangeType != "updated" {
		t.Fatalf("expected 'updated', got %q", history[0].ChangeType)
	}
	if history[2].ChangeType != "created" {
		t.Fatalf("expected 'created' for first version, got %q", history[2].ChangeType)
	}
}

func TestSecretsService_History_NotFound(t *testing.T) {
	svc, _, ctx := testSecretsSetup(t)

	_, err := svc.History(ctx, "development", "NONEXISTENT")
	if err == nil {
		t.Fatal("expected error for nonexistent secret history")
	}
}

func TestSecretsService_GetVersion(t *testing.T) {
	svc, _, ctx := testSecretsSetup(t)

	_, err := svc.Set(ctx, "development", "MULTI_VER", []byte("original"), false)
	if err != nil {
		t.Fatalf("Set: %v", err)
	}
	_, err = svc.Set(ctx, "development", "MULTI_VER", []byte("updated"), true)
	if err != nil {
		t.Fatalf("Set: %v", err)
	}

	// Get version 1
	v1, err := svc.GetVersion(ctx, "development", "MULTI_VER", 1)
	if err != nil {
		t.Fatalf("GetVersion(1): %v", err)
	}
	if string(v1.Value) != "original" {
		t.Fatalf("expected 'original', got %q", v1.Value)
	}

	// Get version 2
	v2, err := svc.GetVersion(ctx, "development", "MULTI_VER", 2)
	if err != nil {
		t.Fatalf("GetVersion(2): %v", err)
	}
	if string(v2.Value) != "updated" {
		t.Fatalf("expected 'updated', got %q", v2.Value)
	}

	// Get nonexistent version
	_, err = svc.GetVersion(ctx, "development", "MULTI_VER", 99)
	if err == nil {
		t.Fatal("expected error for nonexistent version")
	}
}

func TestSecretsService_Rollback(t *testing.T) {
	svc, _, ctx := testSecretsSetup(t)

	_, err := svc.Set(ctx, "development", "ROLLBACK_KEY", []byte("v1-data"), false)
	if err != nil {
		t.Fatalf("Set v1: %v", err)
	}
	_, err = svc.Set(ctx, "development", "ROLLBACK_KEY", []byte("v2-data"), true)
	if err != nil {
		t.Fatalf("Set v2: %v", err)
	}

	// Current value should be v2
	current, _ := svc.Get(ctx, "development", "ROLLBACK_KEY")
	if string(current.Value) != "v2-data" {
		t.Fatalf("expected 'v2-data', got %q", current.Value)
	}

	// Rollback to v1
	err = svc.Rollback(ctx, "development", "ROLLBACK_KEY", 1)
	if err != nil {
		t.Fatalf("Rollback: %v", err)
	}

	// Should now have v1 content
	after, _ := svc.Get(ctx, "development", "ROLLBACK_KEY")
	if string(after.Value) != "v1-data" {
		t.Fatalf("expected 'v1-data' after rollback, got %q", after.Value)
	}
	// Version should be 3 (new version created by rollback)
	if after.Version != 3 {
		t.Fatalf("expected version 3 after rollback, got %d", after.Version)
	}

	// History should show the restore
	history, _ := svc.History(ctx, "development", "ROLLBACK_KEY")
	if history[0].ChangeType != "restored" {
		t.Fatalf("expected 'restored', got %q", history[0].ChangeType)
	}
}

func TestSecretsService_Rollback_NotFound(t *testing.T) {
	svc, _, ctx := testSecretsSetup(t)

	err := svc.Rollback(ctx, "development", "NONEXISTENT", 1)
	if err == nil {
		t.Fatal("expected error for nonexistent secret rollback")
	}
}

func TestSecretsService_Rollback_InvalidVersion(t *testing.T) {
	svc, _, ctx := testSecretsSetup(t)

	_, err := svc.Set(ctx, "development", "RB_KEY", []byte("val"), false)
	if err != nil {
		t.Fatalf("Set: %v", err)
	}

	err = svc.Rollback(ctx, "development", "RB_KEY", 99)
	if err == nil {
		t.Fatal("expected error for invalid rollback version")
	}
}

func TestSecretsService_DeleteAllEnvs(t *testing.T) {
	svc, database, ctx := testSecretsSetup(t)
	projectID := svc.projectID

	// Create a second environment
	envSvc := NewEnvironmentsService(database, projectID)
	if err := envSvc.Create(ctx, "staging"); err != nil {
		t.Fatalf("create staging: %v", err)
	}

	// Set the same key in both envs
	_, err := svc.Set(ctx, "development", "SHARED_KEY", []byte("dev-val"), false)
	if err != nil {
		t.Fatalf("Set dev: %v", err)
	}
	_, err = svc.Set(ctx, "staging", "SHARED_KEY", []byte("stg-val"), false)
	if err != nil {
		t.Fatalf("Set stg: %v", err)
	}

	// Delete from all envs
	if err := svc.DeleteAllEnvs(ctx, "SHARED_KEY"); err != nil {
		t.Fatalf("DeleteAllEnvs: %v", err)
	}

	// Both should be gone
	_, err = svc.Get(ctx, "development", "SHARED_KEY")
	if err == nil {
		t.Fatal("expected error getting deleted secret from development")
	}
	_, err = svc.Get(ctx, "staging", "SHARED_KEY")
	if err == nil {
		t.Fatal("expected error getting deleted secret from staging")
	}
}

func TestSecretsService_ListAllEnvs(t *testing.T) {
	svc, database, ctx := testSecretsSetup(t)
	projectID := svc.projectID

	envSvc := NewEnvironmentsService(database, projectID)
	if err := envSvc.Create(ctx, "staging"); err != nil {
		t.Fatalf("create staging: %v", err)
	}

	_, _ = svc.Set(ctx, "development", "DEV_KEY", []byte("dv"), false)
	_, _ = svc.Set(ctx, "staging", "STG_KEY", []byte("sv"), false)

	all, err := svc.ListAllEnvs(ctx)
	if err != nil {
		t.Fatalf("ListAllEnvs: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("expected 2 environments, got %d", len(all))
	}
	if len(all["development"]) != 1 {
		t.Fatalf("expected 1 secret in development, got %d", len(all["development"]))
	}
	if len(all["staging"]) != 1 {
		t.Fatalf("expected 1 secret in staging, got %d", len(all["staging"]))
	}
}

func TestSecretsService_Set_ResetDeleted(t *testing.T) {
	svc, _, ctx := testSecretsSetup(t)

	_, err := svc.Set(ctx, "development", "RECREATE_KEY", []byte("first"), false)
	if err != nil {
		t.Fatalf("Set: %v", err)
	}

	if err := svc.Delete(ctx, "development", "RECREATE_KEY", false); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	// Re-set the same key — should succeed since the old one is soft-deleted
	version, err := svc.Set(ctx, "development", "RECREATE_KEY", []byte("second"), false)
	if err != nil {
		t.Fatalf("Re-set: %v", err)
	}
	if version != 3 {
		t.Fatalf("expected version 3 after restore (1=created, 2=deleted, 3=restored), got %d", version)
	}

	result, _ := svc.Get(ctx, "development", "RECREATE_KEY")
	if string(result.Value) != "second" {
		t.Fatalf("expected 'second', got %q", result.Value)
	}
}
