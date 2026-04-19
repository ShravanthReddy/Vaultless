// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Shravanth. All rights reserved.

package service

import (
	"context"
	"database/sql"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/vaultless/vaultless/internal/crypto"
	"github.com/vaultless/vaultless/internal/db"
)

func testRunnerSetup(t *testing.T) (*Runner, context.Context) {
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

	_ = database.WithTx(ctx, func(tx *sql.Tx) error {
		_, err := tx.Exec("INSERT INTO projects (id, name, created_at, updated_at) VALUES (?, 'test', datetime('now'), datetime('now'))", projectID)
		return err
	})

	secSvc := NewSecretsService(database, projectID, projectKey, 10, "tester@example.com")
	envSvc := NewEnvironmentsService(database, projectID)
	_ = envSvc.Create(ctx, "development")

	// Add some test secrets
	_, _ = secSvc.Set(ctx, "development", "APP_NAME", []byte("myapp"), false)
	_, _ = secSvc.Set(ctx, "development", "DB_HOST", []byte("localhost"), false)
	_, _ = secSvc.Set(ctx, "development", "DB_PORT", []byte("5432"), false)

	runner := NewRunner(secSvc)
	return runner, ctx
}

func TestRunner_Exec_SimpleCommand(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows")
	}

	runner, ctx := testRunnerSetup(t)

	exitCode, err := runner.Exec(ctx, &RunOptions{
		Command: "true",
		Env:     "development",
	})
	if err != nil {
		t.Fatalf("Exec: %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}
}

func TestRunner_Exec_FailingCommand(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows")
	}

	runner, ctx := testRunnerSetup(t)

	exitCode, err := runner.Exec(ctx, &RunOptions{
		Command: "false",
		Env:     "development",
	})
	if err != nil {
		t.Fatalf("Exec: %v", err)
	}
	if exitCode != 1 {
		t.Fatalf("expected exit code 1, got %d", exitCode)
	}
}

func TestRunner_Exec_NotFoundCommand(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows")
	}

	runner, ctx := testRunnerSetup(t)

	exitCode, err := runner.Exec(ctx, &RunOptions{
		Command: "this-command-does-not-exist-xyzzy",
		Env:     "development",
	})
	if err != nil {
		t.Fatalf("Exec: %v", err)
	}
	if exitCode != 127 {
		t.Fatalf("expected exit code 127 for missing command, got %d", exitCode)
	}
}

func TestRunner_Exec_EnvInjection(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows")
	}

	runner, ctx := testRunnerSetup(t)

	// Use env | grep to verify that secrets are injected
	exitCode, err := runner.Exec(ctx, &RunOptions{
		Command: "sh",
		Args:    []string{"-c", "test \"$APP_NAME\" = myapp && test \"$DB_HOST\" = localhost"},
		Env:     "development",
	})
	if err != nil {
		t.Fatalf("Exec: %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("expected exit 0 (env vars injected correctly), got %d", exitCode)
	}
}

func TestRunner_Exec_OnlyFilter(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows")
	}

	runner, ctx := testRunnerSetup(t)

	// Only DB_* should be injected
	exitCode, err := runner.Exec(ctx, &RunOptions{
		Command: "sh",
		Args:    []string{"-c", "test \"$DB_HOST\" = localhost && test -z \"$APP_NAME\""},
		Env:     "development",
		Only:    "DB_*",
	})
	if err != nil {
		t.Fatalf("Exec: %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("expected exit 0 with Only filter, got %d", exitCode)
	}
}

func TestRunner_Exec_ExcludeFilter(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows")
	}

	runner, ctx := testRunnerSetup(t)

	// Exclude DB_* — only APP_NAME should remain
	exitCode, err := runner.Exec(ctx, &RunOptions{
		Command: "sh",
		Args:    []string{"-c", "test \"$APP_NAME\" = myapp && test -z \"$DB_HOST\""},
		Env:     "development",
		Exclude: "DB_*",
	})
	if err != nil {
		t.Fatalf("Exec: %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("expected exit 0 with Exclude filter, got %d", exitCode)
	}
}

func TestRunner_Exec_NonexistentEnv(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows")
	}

	runner, ctx := testRunnerSetup(t)

	_, err := runner.Exec(ctx, &RunOptions{
		Command: "true",
		Env:     "nonexistent",
	})
	if err == nil {
		t.Fatal("expected error for nonexistent environment")
	}
}

func TestZeroSecretBytes(t *testing.T) {
	data := []byte("sensitive-secret-data")
	ZeroSecretBytes(data)
	for i, b := range data {
		if b != 0 {
			t.Fatalf("byte %d not zeroed: %d", i, b)
		}
	}
}

func TestZeroSecretBytes_Empty(t *testing.T) {
	data := []byte{}
	ZeroSecretBytes(data) // Should not panic
}

func TestApplyGlobFilters(t *testing.T) {
	secrets := map[string][]byte{
		"DB_HOST":    []byte("localhost"),
		"DB_PORT":    []byte("5432"),
		"APP_NAME":   []byte("myapp"),
		"REDIS_HOST": []byte("redis"),
	}

	tests := []struct {
		name    string
		only    string
		exclude string
		wantLen int
	}{
		{"no filters", "", "", 4},
		{"only DB_*", "DB_*", "", 2},
		{"exclude DB_*", "", "DB_*", 2},
		{"only DB_* exclude DB_PORT", "DB_*", "DB_PORT", 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := applyGlobFilters(secrets, tt.only, tt.exclude)
			if len(result) != tt.wantLen {
				t.Fatalf("expected %d, got %d", tt.wantLen, len(result))
			}
		})
	}
}

func TestQuoteEnvValue(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"simple", "simple"},
		{"with space", `"with space"`},
		{"with\nnewline", `"with\nnewline"`},
		{"with'quote", `"with'quote"`},
		{"with#hash", `"with#hash"`},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := quoteEnvValue(tt.input)
			if got != tt.want {
				t.Fatalf("quoteEnvValue(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
