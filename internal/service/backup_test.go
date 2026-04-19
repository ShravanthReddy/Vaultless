// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Shravanth. All rights reserved.

package service

import (
	"os"
	"path/filepath"
	"testing"
)

func testBackupSetup(t *testing.T) (projectPath string, svc *BackupService) {
	t.Helper()
	projectPath = t.TempDir()
	projectID := "test-project-id-1234567890abcdef"

	// Create a minimal database file
	dbPath := filepath.Join(projectPath, "secrets.db")
	if err := os.WriteFile(dbPath, []byte("fake-database-content-for-testing"), 0600); err != nil {
		t.Fatalf("write db: %v", err)
	}

	// Create a config file
	configPath := filepath.Join(projectPath, "config.toml")
	if err := os.WriteFile(configPath, []byte("[project]\nname = \"test\"\n"), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	// Create an audit log
	auditPath := filepath.Join(projectPath, "audit.log")
	if err := os.WriteFile(auditPath, []byte("{\"operation\":\"set\"}\n"), 0600); err != nil {
		t.Fatalf("write audit: %v", err)
	}

	svc = NewBackupService(projectPath, projectID)
	return projectPath, svc
}

func TestBackupService_CreateAndRestore(t *testing.T) {
	projectPath, svc := testBackupSetup(t)
	outputDir := t.TempDir()
	backupFile := filepath.Join(outputDir, "backup.vlt")

	// Create backup
	if err := svc.Create(backupFile); err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Verify backup file exists and has restricted permissions
	info, err := os.Stat(backupFile)
	if err != nil {
		t.Fatalf("stat backup: %v", err)
	}
	if info.Size() == 0 {
		t.Fatal("backup file is empty")
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("expected permissions 0600, got %o", info.Mode().Perm())
	}

	// Destroy original files
	os.Remove(filepath.Join(projectPath, "secrets.db"))
	os.Remove(filepath.Join(projectPath, "config.toml"))
	os.Remove(filepath.Join(projectPath, "audit.log"))

	// Restore
	restoreSvc := NewBackupService(projectPath, "test-project-id-1234567890abcdef")
	if err := restoreSvc.Restore(backupFile); err != nil {
		t.Fatalf("Restore: %v", err)
	}

	// Verify files were restored
	dbData, err := os.ReadFile(filepath.Join(projectPath, "secrets.db"))
	if err != nil {
		t.Fatalf("read restored db: %v", err)
	}
	if string(dbData) != "fake-database-content-for-testing" {
		t.Fatalf("db content mismatch: got %q", string(dbData))
	}

	configData, err := os.ReadFile(filepath.Join(projectPath, "config.toml"))
	if err != nil {
		t.Fatalf("read restored config: %v", err)
	}
	if string(configData) != "[project]\nname = \"test\"\n" {
		t.Fatalf("config content mismatch: got %q", string(configData))
	}

	auditData, err := os.ReadFile(filepath.Join(projectPath, "audit.log"))
	if err != nil {
		t.Fatalf("read restored audit: %v", err)
	}
	if string(auditData) != "{\"operation\":\"set\"}\n" {
		t.Fatalf("audit content mismatch: got %q", string(auditData))
	}
}

func TestBackupService_Create_NoConfigOrAudit(t *testing.T) {
	projectPath := t.TempDir()
	projectID := "test-project-id-minimal-00000000"

	// Only create the database file (required)
	if err := os.WriteFile(filepath.Join(projectPath, "secrets.db"), []byte("db-data"), 0600); err != nil {
		t.Fatalf("write db: %v", err)
	}

	svc := NewBackupService(projectPath, projectID)
	outputDir := t.TempDir()
	backupFile := filepath.Join(outputDir, "backup.vlt")

	if err := svc.Create(backupFile); err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Restore to a new directory
	restorePath := t.TempDir()
	restoreSvc := NewBackupService(restorePath, projectID)
	if err := restoreSvc.Restore(backupFile); err != nil {
		t.Fatalf("Restore: %v", err)
	}

	// Database should be restored
	data, _ := os.ReadFile(filepath.Join(restorePath, "secrets.db"))
	if string(data) != "db-data" {
		t.Fatalf("expected 'db-data', got %q", data)
	}

	// Config and audit should not exist (they were empty)
	if _, err := os.Stat(filepath.Join(restorePath, "config.toml")); !os.IsNotExist(err) {
		t.Fatal("config.toml should not exist when original was missing")
	}
}

func TestBackupService_Create_NoDatabase(t *testing.T) {
	projectPath := t.TempDir()
	svc := NewBackupService(projectPath, "test-id")
	outputDir := t.TempDir()

	err := svc.Create(filepath.Join(outputDir, "backup.vlt"))
	if err == nil {
		t.Fatal("expected error when database doesn't exist")
	}
}

func TestBackupService_Restore_InvalidFile(t *testing.T) {
	projectPath := t.TempDir()
	svc := NewBackupService(projectPath, "test-id")

	// Create a file with wrong magic bytes
	badFile := filepath.Join(t.TempDir(), "bad.vlt")
	os.WriteFile(badFile, []byte("not-a-backup"), 0600)

	err := svc.Restore(badFile)
	if err == nil {
		t.Fatal("expected error for invalid backup file")
	}
}

func TestBackupService_Restore_TamperedFile(t *testing.T) {
	_, svc := testBackupSetup(t)
	outputDir := t.TempDir()
	backupFile := filepath.Join(outputDir, "backup.vlt")

	if err := svc.Create(backupFile); err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Tamper with the backup
	data, _ := os.ReadFile(backupFile)
	if len(data) > 50 {
		data[50] ^= 0xFF // flip a byte
	}
	os.WriteFile(backupFile, data, 0600)

	restorePath := t.TempDir()
	restoreSvc := NewBackupService(restorePath, "test-project-id-1234567890abcdef")
	err := restoreSvc.Restore(backupFile)
	if err == nil {
		t.Fatal("expected integrity check failure for tampered backup")
	}
}

func TestBackupService_Restore_NonexistentFile(t *testing.T) {
	svc := NewBackupService(t.TempDir(), "test-id")
	err := svc.Restore("/nonexistent/path/backup.vlt")
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
}

func TestBackupService_Restore_TooShort(t *testing.T) {
	svc := NewBackupService(t.TempDir(), "test-id")
	shortFile := filepath.Join(t.TempDir(), "short.vlt")
	os.WriteFile(shortFile, []byte("VLT"), 0600)

	err := svc.Restore(shortFile)
	if err == nil {
		t.Fatal("expected error for too-short backup file")
	}
}
