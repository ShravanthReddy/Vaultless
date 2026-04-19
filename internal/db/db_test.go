// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Shravanth. All rights reserved.

package db

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"testing"
)

func TestOpen_CreatesDatabase(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	database, err := Open(dbPath)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer database.Close()

	// Verify migrations ran
	var count int
	err = database.conn.QueryRow("SELECT COUNT(*) FROM _migrations").Scan(&count)
	if err != nil {
		t.Fatalf("query failed: %v", err)
	}
	if count != len(migrations) {
		t.Fatalf("expected %d migrations, got %d", len(migrations), count)
	}
}

func TestIntegrityCheck(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	database, err := Open(dbPath)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer database.Close()

	result, err := database.IntegrityCheck(context.Background())
	if err != nil {
		t.Fatalf("IntegrityCheck failed: %v", err)
	}
	if result != "ok" {
		t.Fatalf("expected 'ok', got '%s'", result)
	}
}

func TestWithTx_Commit(t *testing.T) {
	tmpDir := t.TempDir()
	database, _ := Open(filepath.Join(tmpDir, "test.db"))
	defer database.Close()

	ctx := context.Background()
	err := database.WithTx(ctx, func(tx *sql.Tx) error {
		_, err := tx.Exec("INSERT INTO projects (id, name, created_at, updated_at) VALUES ('1', 'test', '2024-01-01', '2024-01-01')")
		return err
	})
	if err != nil {
		t.Fatalf("WithTx failed: %v", err)
	}

	var name string
	err = database.conn.QueryRow("SELECT name FROM projects WHERE id = '1'").Scan(&name)
	if err != nil {
		t.Fatalf("query failed: %v", err)
	}
	if name != "test" {
		t.Fatalf("expected 'test', got '%s'", name)
	}
}

func TestWithTx_Rollback(t *testing.T) {
	tmpDir := t.TempDir()
	database, _ := Open(filepath.Join(tmpDir, "test.db"))
	defer database.Close()

	ctx := context.Background()
	err := database.WithTx(ctx, func(tx *sql.Tx) error {
		tx.Exec("INSERT INTO projects (id, name, created_at, updated_at) VALUES ('2', 'fail', '2024-01-01', '2024-01-01')")
		return fmt.Errorf("intentional failure")
	})
	if err == nil {
		t.Fatal("expected error")
	}

	var count int
	database.conn.QueryRow("SELECT COUNT(*) FROM projects WHERE id = '2'").Scan(&count)
	if count != 0 {
		t.Fatal("transaction should have been rolled back")
	}
}
