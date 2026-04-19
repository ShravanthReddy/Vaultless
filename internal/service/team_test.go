// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Shravanth. All rights reserved.

package service

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/vaultless/vaultless/internal/crypto"
	"github.com/vaultless/vaultless/internal/db"
)

func testTeamSetup(t *testing.T) (*TeamService, context.Context) {
	t.Helper()
	tmpDir := t.TempDir()
	database, err := db.Open(filepath.Join(tmpDir, "test.db"))
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { database.Close() })

	projectKey, err := crypto.GenerateProjectKey()
	if err != nil {
		t.Fatalf("GenerateProjectKey: %v", err)
	}

	svc := NewTeamService(projectKey, database, "admin@example.com")
	return svc, context.Background()
}

func TestTeamService_Invite(t *testing.T) {
	svc, _ := testTeamSetup(t)

	result, err := svc.Invite("member@example.com")
	if err != nil {
		t.Fatalf("Invite: %v", err)
	}

	if result.Bundle == "" {
		t.Fatal("expected non-empty bundle")
	}
	if result.Passphrase == "" {
		t.Fatal("expected non-empty passphrase")
	}
	if len(result.Passphrase) != 32 { // 16 bytes hex-encoded
		t.Fatalf("expected passphrase length 32, got %d", len(result.Passphrase))
	}
}

func TestTeamService_Invite_JoinRoundtrip(t *testing.T) {
	svc, _ := testTeamSetup(t)

	invite, err := svc.Invite("newmember@example.com")
	if err != nil {
		t.Fatalf("Invite: %v", err)
	}

	// Join should decrypt and return the project key
	recoveredKey, err := Join(invite.Bundle, invite.Passphrase)
	if err != nil {
		t.Fatalf("Join: %v", err)
	}

	// The recovered key should match the original project key
	if len(recoveredKey) != crypto.KeySize {
		t.Fatalf("expected key size %d, got %d", crypto.KeySize, len(recoveredKey))
	}

	// Verify it matches by comparing with the service's key
	for i := range svc.projectKey {
		if recoveredKey[i] != svc.projectKey[i] {
			t.Fatalf("key mismatch at byte %d", i)
		}
	}
}

func TestTeamService_Join_WrongPassphrase(t *testing.T) {
	svc, _ := testTeamSetup(t)

	invite, err := svc.Invite("member@example.com")
	if err != nil {
		t.Fatalf("Invite: %v", err)
	}

	_, err = Join(invite.Bundle, "wrong-passphrase")
	if err == nil {
		t.Fatal("expected error with wrong passphrase")
	}
}

func TestTeamService_Join_InvalidBundle(t *testing.T) {
	_, err := Join("not-valid-base64!!!", "passphrase")
	if err == nil {
		t.Fatal("expected error with invalid bundle")
	}
}

func TestTeamService_List(t *testing.T) {
	svc, ctx := testTeamSetup(t)

	// Initially empty
	members, err := svc.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(members) != 0 {
		t.Fatalf("expected 0 members, got %d", len(members))
	}

	// Invite adds a member record
	_, _ = svc.Invite("alice@example.com")
	_, _ = svc.Invite("bob@example.com")

	members, err = svc.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(members) != 2 {
		t.Fatalf("expected 2 members, got %d", len(members))
	}
}

func TestTeamService_Remove(t *testing.T) {
	svc, ctx := testTeamSetup(t)

	_, _ = svc.Invite("removeme@example.com")

	err := svc.Remove(ctx, "removeme@example.com")
	if err != nil {
		t.Fatalf("Remove: %v", err)
	}

	// Should not appear in list
	members, _ := svc.List(ctx)
	for _, m := range members {
		if m.Email == "removeme@example.com" {
			t.Fatal("removed member should not appear in list")
		}
	}
}

func TestTeamService_Remove_NotFound(t *testing.T) {
	svc, ctx := testTeamSetup(t)

	err := svc.Remove(ctx, "nonexistent@example.com")
	if err == nil {
		t.Fatal("expected error removing nonexistent member")
	}
}

func TestTeamService_Invite_DuplicateEmail(t *testing.T) {
	svc, ctx := testTeamSetup(t)

	_, err := svc.Invite("dup@example.com")
	if err != nil {
		t.Fatalf("first Invite: %v", err)
	}

	// Second invite for same email — the invite bundle is still generated
	// but the DB insert might fail silently (service swallows the error)
	result, err := svc.Invite("dup@example.com")
	if err != nil {
		t.Fatalf("second Invite: %v", err)
	}
	if result.Bundle == "" {
		t.Fatal("expected bundle even for duplicate invite")
	}

	// Should still have only 1 member in the list
	members, _ := svc.List(ctx)
	if len(members) != 1 {
		t.Fatalf("expected 1 member, got %d", len(members))
	}
}
