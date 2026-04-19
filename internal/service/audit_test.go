// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Shravanth. All rights reserved.

package service

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/vaultless/vaultless/internal/crypto"
	"github.com/vaultless/vaultless/internal/models"
)

func testAuditSetup(t *testing.T) *AuditWriter {
	t.Helper()
	tmpDir := t.TempDir()
	projectKey, _ := crypto.GenerateProjectKey()
	return NewAuditWriter(filepath.Join(tmpDir, "audit.log"), projectKey)
}

func TestAuditWriter_Log(t *testing.T) {
	aw := testAuditSetup(t)

	entry := &models.AuditEntry{
		Operation:   "set",
		User:        "tester@example.com",
		Environment: "development",
		Key:         "API_KEY",
		Success:     true,
	}

	if err := aw.Log(entry); err != nil {
		t.Fatalf("Log: %v", err)
	}

	if entry.ID == "" {
		t.Fatal("expected ID to be set")
	}
	if entry.Timestamp.IsZero() {
		t.Fatal("expected Timestamp to be set")
	}
	if entry.HMAC == "" {
		t.Fatal("expected HMAC to be set")
	}
}

func TestAuditWriter_LogAndQuery(t *testing.T) {
	aw := testAuditSetup(t)

	entries := []*models.AuditEntry{
		{Operation: "set", User: "alice@example.com", Environment: "development", Key: "DB_HOST", Success: true},
		{Operation: "get", User: "bob@example.com", Environment: "staging", Key: "DB_HOST", Success: true},
		{Operation: "delete", User: "alice@example.com", Environment: "development", Key: "API_KEY", Success: true},
		{Operation: "set", User: "alice@example.com", Environment: "production", Key: "SECRET", Success: false},
	}

	for _, e := range entries {
		if err := aw.Log(e); err != nil {
			t.Fatalf("Log: %v", err)
		}
	}

	// Query all
	all, err := aw.Query(&AuditQuery{Limit: 100})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(all) != 4 {
		t.Fatalf("expected 4 entries, got %d", len(all))
	}

	// Newest first
	if all[0].Operation != "set" || all[0].Key != "SECRET" {
		t.Fatalf("expected newest entry first, got op=%q key=%q", all[0].Operation, all[0].Key)
	}
}

func TestAuditWriter_Query_FilterByKey(t *testing.T) {
	aw := testAuditSetup(t)

	_ = aw.Log(&models.AuditEntry{Operation: "set", Key: "TARGET_KEY", Success: true})
	_ = aw.Log(&models.AuditEntry{Operation: "set", Key: "OTHER_KEY", Success: true})
	_ = aw.Log(&models.AuditEntry{Operation: "get", Key: "TARGET_KEY", Success: true})

	results, err := aw.Query(&AuditQuery{Key: "TARGET_KEY", Limit: 100})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 results for TARGET_KEY, got %d", len(results))
	}
}

func TestAuditWriter_Query_FilterByUser(t *testing.T) {
	aw := testAuditSetup(t)

	_ = aw.Log(&models.AuditEntry{Operation: "set", User: "alice@example.com", Success: true})
	_ = aw.Log(&models.AuditEntry{Operation: "set", User: "bob@example.com", Success: true})

	results, err := aw.Query(&AuditQuery{User: "alice@example.com", Limit: 100})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result for alice, got %d", len(results))
	}
}

func TestAuditWriter_Query_FilterByEnv(t *testing.T) {
	aw := testAuditSetup(t)

	_ = aw.Log(&models.AuditEntry{Operation: "set", Environment: "development", Success: true})
	_ = aw.Log(&models.AuditEntry{Operation: "set", Environment: "production", Success: true})
	_ = aw.Log(&models.AuditEntry{Operation: "get", Environment: "development", Success: true})

	results, err := aw.Query(&AuditQuery{Environment: "development", Limit: 100})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 results for development, got %d", len(results))
	}
}

func TestAuditWriter_Query_TimeRange(t *testing.T) {
	aw := testAuditSetup(t)

	_ = aw.Log(&models.AuditEntry{Operation: "set", Key: "KEY1", Success: true})

	// Small sleep to ensure time difference
	midpoint := time.Now().UTC()

	_ = aw.Log(&models.AuditEntry{Operation: "set", Key: "KEY2", Success: true})

	// Query after midpoint
	results, err := aw.Query(&AuditQuery{From: &midpoint, Limit: 100})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result after midpoint, got %d", len(results))
	}
	if results[0].Key != "KEY2" {
		t.Fatalf("expected KEY2, got %q", results[0].Key)
	}
}

func TestAuditWriter_Query_LimitAndOffset(t *testing.T) {
	aw := testAuditSetup(t)

	for i := 0; i < 10; i++ {
		_ = aw.Log(&models.AuditEntry{Operation: "set", Key: "KEY", Success: true})
	}

	// Limit
	results, _ := aw.Query(&AuditQuery{Limit: 3})
	if len(results) != 3 {
		t.Fatalf("expected 3 results with limit, got %d", len(results))
	}

	// Offset
	results, _ = aw.Query(&AuditQuery{Limit: 5, Offset: 8})
	if len(results) != 2 {
		t.Fatalf("expected 2 results with offset 8, got %d", len(results))
	}
}

func TestAuditWriter_Query_DefaultLimit(t *testing.T) {
	aw := testAuditSetup(t)

	for i := 0; i < 60; i++ {
		_ = aw.Log(&models.AuditEntry{Operation: "set", Key: "KEY", Success: true})
	}

	results, _ := aw.Query(&AuditQuery{})
	if len(results) != 50 {
		t.Fatalf("expected default limit of 50, got %d", len(results))
	}
}

func TestAuditWriter_Query_EmptyLog(t *testing.T) {
	aw := testAuditSetup(t)

	results, err := aw.Query(&AuditQuery{Limit: 10})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if results != nil {
		t.Fatalf("expected nil for empty log, got %d entries", len(results))
	}
}

func TestAuditWriter_Verify(t *testing.T) {
	aw := testAuditSetup(t)

	for i := 0; i < 5; i++ {
		_ = aw.Log(&models.AuditEntry{
			Operation:   "set",
			User:        "tester@example.com",
			Environment: "dev",
			Key:         "KEY",
			Success:     true,
		})
	}

	valid, invalid, err := aw.Verify()
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if valid != 5 {
		t.Fatalf("expected 5 valid, got %d", valid)
	}
	if invalid != 0 {
		t.Fatalf("expected 0 invalid, got %d", invalid)
	}
}

func TestAuditWriter_Verify_EmptyLog(t *testing.T) {
	aw := testAuditSetup(t)

	valid, invalid, err := aw.Verify()
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if valid != 0 || invalid != 0 {
		t.Fatalf("expected 0/0 for empty log, got %d/%d", valid, invalid)
	}
}

func TestAuditWriter_Verify_TamperedEntry(t *testing.T) {
	aw := testAuditSetup(t)

	_ = aw.Log(&models.AuditEntry{Operation: "set", Key: "KEY", Success: true})

	// Tamper with the log file
	data, _ := filepath.Glob(filepath.Dir(aw.path) + "/*")
	if len(data) == 0 {
		t.Fatal("no audit file found")
	}

	// Append a tampered line
	f, _ := filepath.Abs(aw.path)
	fd, _ := os.OpenFile(f, os.O_APPEND|os.O_WRONLY, 0600)
	fd.WriteString(`{"id":"fake","operation":"set","key":"KEY","success":true,"hmac":"invalid-hmac"}` + "\n")
	fd.Close()

	valid, invalid, err := aw.Verify()
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if valid != 1 {
		t.Fatalf("expected 1 valid, got %d", valid)
	}
	if invalid != 1 {
		t.Fatalf("expected 1 invalid, got %d", invalid)
	}
}

func TestAuditWriter_Verify_WrongKey(t *testing.T) {
	tmpDir := t.TempDir()
	auditPath := filepath.Join(tmpDir, "audit.log")

	// Write with one key
	key1, _ := crypto.GenerateProjectKey()
	aw1 := NewAuditWriter(auditPath, key1)
	_ = aw1.Log(&models.AuditEntry{Operation: "set", Key: "KEY", Success: true})

	// Verify with a different key
	key2, _ := crypto.GenerateProjectKey()
	aw2 := NewAuditWriter(auditPath, key2)
	valid, invalid, err := aw2.Verify()
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if valid != 0 {
		t.Fatalf("expected 0 valid with wrong key, got %d", valid)
	}
	if invalid != 1 {
		t.Fatalf("expected 1 invalid with wrong key, got %d", invalid)
	}
}
