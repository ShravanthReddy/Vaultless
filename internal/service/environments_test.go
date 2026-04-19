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

func testEnvSetup(t *testing.T) (*EnvironmentsService, *SecretsService, context.Context) {
	t.Helper()
	tmpDir := t.TempDir()
	database, err := db.Open(filepath.Join(tmpDir, "test.db"))
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { database.Close() })

	ctx := context.Background()
	projectID := crypto.GenerateUUID()
	projectKey, _ := crypto.GenerateProjectKey()

	err = database.WithTx(ctx, func(tx *sql.Tx) error {
		_, err := tx.Exec("INSERT INTO projects (id, name, created_at, updated_at) VALUES (?, 'test', datetime('now'), datetime('now'))", projectID)
		return err
	})
	if err != nil {
		t.Fatalf("insert project: %v", err)
	}

	envSvc := NewEnvironmentsService(database, projectID)
	secSvc := NewSecretsService(database, projectID, projectKey, 10, "tester@example.com")
	return envSvc, secSvc, ctx
}

func TestEnvironmentsService_Create(t *testing.T) {
	svc, _, ctx := testEnvSetup(t)

	if err := svc.Create(ctx, "production"); err != nil {
		t.Fatalf("Create: %v", err)
	}

	envs, err := svc.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(envs) != 1 {
		t.Fatalf("expected 1 env, got %d", len(envs))
	}
	if envs[0].Name != "production" {
		t.Fatalf("expected 'production', got %q", envs[0].Name)
	}
}

func TestEnvironmentsService_Create_Duplicate(t *testing.T) {
	svc, _, ctx := testEnvSetup(t)

	if err := svc.Create(ctx, "staging"); err != nil {
		t.Fatalf("Create: %v", err)
	}

	err := svc.Create(ctx, "staging")
	if err == nil {
		t.Fatal("expected error for duplicate environment")
	}
	var alreadyExists *models.ErrAlreadyExists
	if !errors.As(err, &alreadyExists) {
		t.Fatalf("expected ErrAlreadyExists, got %T: %v", err, err)
	}
}

func TestEnvironmentsService_Create_InvalidName(t *testing.T) {
	svc, _, ctx := testEnvSetup(t)

	tests := []struct {
		name    string
		envName string
	}{
		{"uppercase", "Production"},
		{"starts with number", "1env"},
		{"contains underscore", "my_env"},
		{"empty", ""},
		{"contains space", "my env"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := svc.Create(ctx, tt.envName)
			if err == nil {
				t.Fatalf("expected validation error for %q", tt.envName)
			}
			var valErr *models.ErrValidation
			if !errors.As(err, &valErr) {
				t.Fatalf("expected ErrValidation, got %T: %v", err, err)
			}
		})
	}
}

func TestEnvironmentsService_Delete(t *testing.T) {
	svc, _, ctx := testEnvSetup(t)

	if err := svc.Create(ctx, "temp"); err != nil {
		t.Fatalf("Create: %v", err)
	}

	if err := svc.Delete(ctx, "temp"); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	envs, _ := svc.List(ctx)
	if len(envs) != 0 {
		t.Fatalf("expected 0 envs after delete, got %d", len(envs))
	}
}

func TestEnvironmentsService_Delete_NotFound(t *testing.T) {
	svc, _, ctx := testEnvSetup(t)

	err := svc.Delete(ctx, "nonexistent")
	if err == nil {
		t.Fatal("expected error deleting nonexistent env")
	}
	var notFound *models.ErrNotFound
	if !errors.As(err, &notFound) {
		t.Fatalf("expected ErrNotFound, got %T: %v", err, err)
	}
}

func TestEnvironmentsService_Delete_CascadesSecrets(t *testing.T) {
	svc, secSvc, ctx := testEnvSetup(t)

	if err := svc.Create(ctx, "ephemeral"); err != nil {
		t.Fatalf("Create: %v", err)
	}

	_, err := secSvc.Set(ctx, "ephemeral", "SECRET_KEY", []byte("value"), false)
	if err != nil {
		t.Fatalf("Set: %v", err)
	}

	if err := svc.Delete(ctx, "ephemeral"); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	// Secret should not be accessible via its old environment
	_, err = secSvc.Get(ctx, "ephemeral", "SECRET_KEY")
	if err == nil {
		t.Fatal("expected error getting secret from deleted env")
	}
}

func TestEnvironmentsService_List_Multiple(t *testing.T) {
	svc, _, ctx := testEnvSetup(t)

	names := []string{"alpha", "beta", "gamma"}
	for _, n := range names {
		if err := svc.Create(ctx, n); err != nil {
			t.Fatalf("Create %s: %v", n, err)
		}
	}

	envs, err := svc.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(envs) != 3 {
		t.Fatalf("expected 3 envs, got %d", len(envs))
	}
	// Should be sorted alphabetically
	if envs[0].Name != "alpha" || envs[1].Name != "beta" || envs[2].Name != "gamma" {
		t.Fatalf("unexpected order: %v", envs)
	}
}

func TestEnvironmentsService_List_SecretCount(t *testing.T) {
	svc, secSvc, ctx := testEnvSetup(t)

	if err := svc.Create(ctx, "counted"); err != nil {
		t.Fatalf("Create: %v", err)
	}

	_, _ = secSvc.Set(ctx, "counted", "KEY_ONE", []byte("v"), false)
	_, _ = secSvc.Set(ctx, "counted", "KEY_TWO", []byte("v"), false)

	envs, _ := svc.List(ctx)
	var found bool
	for _, e := range envs {
		if e.Name == "counted" {
			found = true
			if e.SecretCount != 2 {
				t.Fatalf("expected SecretCount 2, got %d", e.SecretCount)
			}
		}
	}
	if !found {
		t.Fatal("env 'counted' not found in list")
	}
}

func TestEnvironmentsService_Clone(t *testing.T) {
	svc, secSvc, ctx := testEnvSetup(t)

	if err := svc.Create(ctx, "source"); err != nil {
		t.Fatalf("Create source: %v", err)
	}
	_, _ = secSvc.Set(ctx, "source", "DB_HOST", []byte("localhost"), false)
	_, _ = secSvc.Set(ctx, "source", "DB_PORT", []byte("5432"), false)

	if err := svc.Clone(ctx, "source", "target"); err != nil {
		t.Fatalf("Clone: %v", err)
	}

	// Target should exist
	envs, _ := svc.List(ctx)
	var targetFound bool
	for _, e := range envs {
		if e.Name == "target" {
			targetFound = true
			if e.SecretCount != 2 {
				t.Fatalf("expected 2 secrets in target, got %d", e.SecretCount)
			}
		}
	}
	if !targetFound {
		t.Fatal("target env not created by Clone")
	}

	// Secrets should be accessible in target
	result, err := secSvc.Get(ctx, "target", "DB_HOST")
	if err != nil {
		t.Fatalf("Get from target: %v", err)
	}
	if string(result.Value) != "localhost" {
		t.Fatalf("expected 'localhost', got %q", result.Value)
	}
}

func TestEnvironmentsService_Clone_SourceNotFound(t *testing.T) {
	svc, _, ctx := testEnvSetup(t)

	err := svc.Clone(ctx, "nonexistent", "target")
	if err == nil {
		t.Fatal("expected error cloning from nonexistent source")
	}
	var notFound *models.ErrNotFound
	if !errors.As(err, &notFound) {
		t.Fatalf("expected ErrNotFound, got %T: %v", err, err)
	}
}

func TestEnvironmentsService_Clone_TargetExists(t *testing.T) {
	svc, _, ctx := testEnvSetup(t)

	_ = svc.Create(ctx, "src")
	_ = svc.Create(ctx, "dst")

	err := svc.Clone(ctx, "src", "dst")
	if err == nil {
		t.Fatal("expected error cloning to existing target")
	}
	var alreadyExists *models.ErrAlreadyExists
	if !errors.As(err, &alreadyExists) {
		t.Fatalf("expected ErrAlreadyExists, got %T: %v", err, err)
	}
}

func TestEnvironmentsService_Diff(t *testing.T) {
	svc, secSvc, ctx := testEnvSetup(t)

	_ = svc.Create(ctx, "env-a")
	_ = svc.Create(ctx, "env-b")

	_, _ = secSvc.Set(ctx, "env-a", "SHARED", []byte("v"), false)
	_, _ = secSvc.Set(ctx, "env-a", "ONLY_A", []byte("v"), false)
	_, _ = secSvc.Set(ctx, "env-b", "SHARED", []byte("v"), false)
	_, _ = secSvc.Set(ctx, "env-b", "ONLY_B", []byte("v"), false)

	diff, err := svc.Diff(ctx, "env-a", "env-b")
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}

	if len(diff.OnlyInEnv1) != 1 || diff.OnlyInEnv1[0] != "ONLY_A" {
		t.Fatalf("expected OnlyInEnv1=[ONLY_A], got %v", diff.OnlyInEnv1)
	}
	if len(diff.OnlyInEnv2) != 1 || diff.OnlyInEnv2[0] != "ONLY_B" {
		t.Fatalf("expected OnlyInEnv2=[ONLY_B], got %v", diff.OnlyInEnv2)
	}
	if len(diff.InBoth) != 1 || diff.InBoth[0] != "SHARED" {
		t.Fatalf("expected InBoth=[SHARED], got %v", diff.InBoth)
	}
}

func TestEnvironmentsService_Diff_NotFound(t *testing.T) {
	svc, _, ctx := testEnvSetup(t)

	_ = svc.Create(ctx, "existing")

	_, err := svc.Diff(ctx, "existing", "nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent env in diff")
	}

	_, err = svc.Diff(ctx, "nonexistent", "existing")
	if err == nil {
		t.Fatal("expected error for nonexistent env in diff")
	}
}

func TestEnvironmentsService_Diff_Empty(t *testing.T) {
	svc, _, ctx := testEnvSetup(t)

	_ = svc.Create(ctx, "empty-a")
	_ = svc.Create(ctx, "empty-b")

	diff, err := svc.Diff(ctx, "empty-a", "empty-b")
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if len(diff.OnlyInEnv1) != 0 || len(diff.OnlyInEnv2) != 0 || len(diff.InBoth) != 0 {
		t.Fatal("expected empty diff for two empty environments")
	}
}
