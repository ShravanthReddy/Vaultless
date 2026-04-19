// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Shravanth. All rights reserved.

package db

import (
	"errors"
	"testing"
	"time"

	"github.com/vaultless/vaultless/internal/models"
)

func TestTeamStore_Add_And_List(t *testing.T) {
	database, ctx := setupTestDB(t)
	store := NewTeamStore(database)

	member := &models.TeamMember{
		ID:        "mem-1",
		Email:     "alice@example.com",
		Role:      "member",
		InvitedBy: "admin@example.com",
		CreatedAt: time.Now().UTC(),
	}

	if err := store.Add(ctx, member); err != nil {
		t.Fatalf("Add: %v", err)
	}

	members, err := store.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(members) != 1 {
		t.Fatalf("expected 1, got %d", len(members))
	}
	if members[0].Email != "alice@example.com" {
		t.Fatalf("expected 'alice@example.com', got %q", members[0].Email)
	}
	if members[0].Role != "member" {
		t.Fatalf("expected 'member', got %q", members[0].Role)
	}
}

func TestTeamStore_Add_Duplicate(t *testing.T) {
	database, ctx := setupTestDB(t)
	store := NewTeamStore(database)

	member := &models.TeamMember{
		ID: "mem-dup1", Email: "dup@example.com", Role: "member",
		InvitedBy: "admin", CreatedAt: time.Now().UTC(),
	}
	_ = store.Add(ctx, member)

	member2 := &models.TeamMember{
		ID: "mem-dup2", Email: "dup@example.com", Role: "member",
		InvitedBy: "admin", CreatedAt: time.Now().UTC(),
	}
	err := store.Add(ctx, member2)
	if err == nil {
		t.Fatal("expected error for duplicate email")
	}
}

func TestTeamStore_Remove(t *testing.T) {
	database, ctx := setupTestDB(t)
	store := NewTeamStore(database)

	member := &models.TeamMember{
		ID: "mem-rem", Email: "remove@example.com", Role: "member",
		InvitedBy: "admin", CreatedAt: time.Now().UTC(),
	}
	_ = store.Add(ctx, member)

	if err := store.Remove(ctx, "remove@example.com"); err != nil {
		t.Fatalf("Remove: %v", err)
	}

	members, _ := store.List(ctx)
	if len(members) != 0 {
		t.Fatalf("expected 0 after remove, got %d", len(members))
	}
}

func TestTeamStore_Remove_NotFound(t *testing.T) {
	database, ctx := setupTestDB(t)
	store := NewTeamStore(database)

	err := store.Remove(ctx, "nonexistent@example.com")
	if err == nil {
		t.Fatal("expected error removing nonexistent member")
	}
	var notFound *models.ErrNotFound
	if !errors.As(err, &notFound) {
		t.Fatalf("expected ErrNotFound, got %T: %v", err, err)
	}
}

func TestTeamStore_Remove_AlreadyRemoved(t *testing.T) {
	database, ctx := setupTestDB(t)
	store := NewTeamStore(database)

	member := &models.TeamMember{
		ID: "mem-dblrem", Email: "dblrem@example.com", Role: "member",
		InvitedBy: "admin", CreatedAt: time.Now().UTC(),
	}
	_ = store.Add(ctx, member)
	_ = store.Remove(ctx, "dblrem@example.com")

	// Second remove should error
	err := store.Remove(ctx, "dblrem@example.com")
	if err == nil {
		t.Fatal("expected error removing already-removed member")
	}
}

func TestTeamStore_List_ExcludesRemoved(t *testing.T) {
	database, ctx := setupTestDB(t)
	store := NewTeamStore(database)

	_ = store.Add(ctx, &models.TeamMember{
		ID: "mem-a", Email: "active@example.com", Role: "member",
		InvitedBy: "admin", CreatedAt: time.Now().UTC(),
	})
	_ = store.Add(ctx, &models.TeamMember{
		ID: "mem-r", Email: "removed@example.com", Role: "member",
		InvitedBy: "admin", CreatedAt: time.Now().UTC(),
	})
	_ = store.Remove(ctx, "removed@example.com")

	members, _ := store.List(ctx)
	if len(members) != 1 {
		t.Fatalf("expected 1 active member, got %d", len(members))
	}
	if members[0].Email != "active@example.com" {
		t.Fatalf("expected active member, got %q", members[0].Email)
	}
}

func TestTeamStore_List_Empty(t *testing.T) {
	database, ctx := setupTestDB(t)
	store := NewTeamStore(database)

	members, err := store.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(members) != 0 {
		t.Fatalf("expected 0 members, got %d", len(members))
	}
}
