// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Shravanth. All rights reserved.

package service

import (
	"context"
	"fmt"
	"time"

	"github.com/vaultless/vaultless/internal/crypto"
	"github.com/vaultless/vaultless/internal/db"
	"github.com/vaultless/vaultless/internal/models"
)

// TeamService handles team key exchange and member management.
type TeamService struct {
	projectKey []byte
	store      *db.TeamStore
	identity   string
}

func NewTeamService(projectKey []byte, database *db.DB, identity string) *TeamService {
	return &TeamService{
		projectKey: projectKey,
		store:      db.NewTeamStore(database),
		identity:   identity,
	}
}

// InviteResult contains the invite bundle and passphrase.
type InviteResult struct {
	Bundle     string
	Passphrase string
}

// Invite creates an encrypted bundle for a new team member.
func (s *TeamService) Invite(email string) (*InviteResult, error) {
	// Generate a random passphrase
	passphraseBytes, err := crypto.GenerateRandomBytes(16)
	if err != nil {
		return nil, fmt.Errorf("failed to generate passphrase: %w", err)
	}
	passphrase := fmt.Sprintf("%x", passphraseBytes)

	bundle, err := crypto.CreateInviteBundle(s.projectKey, passphrase)
	if err != nil {
		return nil, err
	}

	// Record the invited member in the database
	member := &models.TeamMember{
		ID:        crypto.GenerateUUID(),
		Email:     email,
		Role:      "member",
		InvitedBy: s.identity,
		CreatedAt: time.Now().UTC(),
	}
	if err := s.store.Add(context.Background(), member); err != nil {
		// Non-fatal: invite still works even if recording fails (e.g., duplicate)
		_ = err
	}

	return &InviteResult{
		Bundle:     bundle,
		Passphrase: passphrase,
	}, nil
}

// List returns all active team members.
func (s *TeamService) List(ctx context.Context) ([]models.TeamMember, error) {
	return s.store.List(ctx)
}

// Remove soft-deletes a team member by email.
func (s *TeamService) Remove(ctx context.Context, email string) error {
	return s.store.Remove(ctx, email)
}

// Join decrypts an invite bundle and returns the project key.
func Join(bundle, passphrase string) ([]byte, error) {
	return crypto.DecryptInviteBundle(bundle, passphrase)
}
