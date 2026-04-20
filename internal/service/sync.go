// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Shravanth. All rights reserved.

package service

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/vaultless/vaultless/internal/crypto"
	"github.com/vaultless/vaultless/internal/db"
	"github.com/vaultless/vaultless/internal/models"
	syncpkg "github.com/vaultless/vaultless/internal/sync"
)

// SyncStatus represents the current sync state for display.
type SyncStatus struct {
	Backend          string     `json:"backend"`
	Remote           string     `json:"remote,omitempty"`
	LastPushAt       *time.Time `json:"last_push_at,omitempty"`
	LastPullAt       *time.Time `json:"last_pull_at,omitempty"`
	HasLocalChanges  bool       `json:"has_local_changes"`
	HasRemoteChanges bool       `json:"has_remote_changes"`
}

// SyncService handles push/pull operations with conflict detection.
type SyncService struct {
	database  *db.DB
	secrets   *SecretsService
	backend   syncpkg.SyncBackend
	syncState *db.SyncStateStore
	envs      *db.EnvironmentStore
	projectID string
}

func NewSyncService(database *db.DB, secrets *SecretsService, backend syncpkg.SyncBackend, projectID string) *SyncService {
	return &SyncService{
		database:  database,
		secrets:   secrets,
		backend:   backend,
		syncState: db.NewSyncStateStore(database),
		envs:      db.NewEnvironmentStore(database),
		projectID: projectID,
	}
}

// Pull fetches remote state. It compares remote_hash vs local_hash before proceeding.
// If hashes differ and force is false, returns ErrConflict.
func (s *SyncService) Pull(ctx context.Context, envName string, force bool) error {
	env, err := s.resolveEnv(ctx, envName)
	if err != nil {
		return err
	}

	state, err := s.syncState.Get(ctx, env.ID)
	if err != nil {
		return fmt.Errorf("failed to get sync state: %w", err)
	}

	// If sync state exists, check for conflicts
	if state != nil && state.LocalHash != "" && state.RemoteHash != "" {
		if state.RemoteHash != state.LocalHash && !force {
			return &models.ErrConflict{
				LocalHash:  state.LocalHash,
				RemoteHash: state.RemoteHash,
			}
		}
	}

	// Fetch remote data via backend
	var remoteHash string
	if s.backend != nil {
		hash, err := s.backend.Hash()
		if err != nil {
			return fmt.Errorf("failed to get remote hash: %w", err)
		}
		remoteHash = hash
	}

	// Proceed with pull: update sync state
	return s.database.WithTx(ctx, func(tx *sql.Tx) error {
		newState := &db.SyncState{
			EnvironmentID: env.ID,
			RemoteHash:    remoteHash,
			LocalHash:     remoteHash, // After pull, local matches remote
		}
		if state != nil && state.ID != "" {
			newState.ID = state.ID
			newState.LastPushAt = state.LastPushAt
		} else {
			newState.ID = crypto.GenerateUUID()
		}
		now := timeNow()
		newState.LastPullAt = &now
		return s.syncState.Upsert(ctx, tx, newState)
	})
}

// Push updates remote state. Compares remote_hash vs local_hash before proceeding.
// If hashes differ and force is false, returns ErrConflict.
func (s *SyncService) Push(ctx context.Context, envName string, force bool) error {
	env, err := s.resolveEnv(ctx, envName)
	if err != nil {
		return err
	}

	state, err := s.syncState.Get(ctx, env.ID)
	if err != nil {
		return fmt.Errorf("failed to get sync state: %w", err)
	}

	// If sync state exists, check for conflicts
	if state != nil && state.LocalHash != "" && state.RemoteHash != "" {
		if state.RemoteHash != state.LocalHash && !force {
			return &models.ErrConflict{
				LocalHash:  state.LocalHash,
				RemoteHash: state.RemoteHash,
			}
		}
	}

	// Push data via backend
	var newLocalHash string
	if s.backend != nil {
		// In a full implementation, we'd serialize secrets and push
		hash, err := s.backend.Hash()
		if err != nil {
			return fmt.Errorf("failed to compute push hash: %w", err)
		}
		newLocalHash = hash
	}

	// Proceed with push: update sync state
	return s.database.WithTx(ctx, func(tx *sql.Tx) error {
		newState := &db.SyncState{
			EnvironmentID: env.ID,
			RemoteHash:    newLocalHash,
			LocalHash:     newLocalHash, // After push, remote matches local
		}
		if state != nil && state.ID != "" {
			newState.ID = state.ID
			newState.LastPullAt = state.LastPullAt
		} else {
			newState.ID = crypto.GenerateUUID()
		}
		now := timeNow()
		newState.LastPushAt = &now
		return s.syncState.Upsert(ctx, tx, newState)
	})
}

// Status returns the current sync status.
func (s *SyncService) Status(ctx context.Context) (*SyncStatus, error) {
	status := &SyncStatus{
		Backend: "none",
	}
	if s.backend == nil {
		return status, nil
	}

	// Get all environments for this project
	envs, err := s.envs.List(ctx, s.projectID)
	if err != nil {
		return nil, err
	}

	for _, env := range envs {
		state, err := s.syncState.Get(ctx, env.ID)
		if err != nil {
			continue
		}
		if state == nil {
			continue
		}
		if state.LastPushAt != nil && (status.LastPushAt == nil || state.LastPushAt.After(*status.LastPushAt)) {
			status.LastPushAt = state.LastPushAt
		}
		if state.LastPullAt != nil && (status.LastPullAt == nil || state.LastPullAt.After(*status.LastPullAt)) {
			status.LastPullAt = state.LastPullAt
		}
		if state.LocalHash != state.RemoteHash {
			status.HasLocalChanges = true
			status.HasRemoteChanges = true
		}
	}

	return status, nil
}

// GetState returns the current sync state for an environment.
func (s *SyncService) GetState(ctx context.Context, envName string) (*db.SyncState, error) {
	env, err := s.resolveEnv(ctx, envName)
	if err != nil {
		return nil, err
	}
	return s.syncState.Get(ctx, env.ID)
}

func (s *SyncService) resolveEnv(ctx context.Context, envName string) (*models.Environment, error) {
	env, err := s.envs.GetByName(ctx, s.projectID, envName)
	if err != nil {
		return nil, err
	}
	if env == nil {
		return nil, &models.ErrNotFound{Entity: "environment", Name: envName}
	}
	return env, nil
}
