// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Shravanth. All rights reserved.

package db

import (
	"context"
	"database/sql"
	"time"
)

// SyncStateStore handles sync state tracking.
type SyncStateStore struct {
	db *DB
}

func NewSyncStateStore(db *DB) *SyncStateStore {
	return &SyncStateStore{db: db}
}

type SyncState struct {
	ID            string
	EnvironmentID string
	LastPushAt    *time.Time
	LastPullAt    *time.Time
	RemoteHash    string
	LocalHash     string
}

func (s *SyncStateStore) Get(ctx context.Context, envID string) (*SyncState, error) {
	row := s.db.conn.QueryRowContext(ctx,
		"SELECT id, environment_id, last_push_at, last_pull_at, remote_hash, local_hash FROM sync_state WHERE environment_id = ?",
		envID,
	)

	var state SyncState
	var lastPush, lastPull sql.NullString
	if err := row.Scan(&state.ID, &state.EnvironmentID, &lastPush, &lastPull, &state.RemoteHash, &state.LocalHash); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	if lastPush.Valid {
		t, _ := time.Parse(time.RFC3339, lastPush.String)
		state.LastPushAt = &t
	}
	if lastPull.Valid {
		t, _ := time.Parse(time.RFC3339, lastPull.String)
		state.LastPullAt = &t
	}
	return &state, nil
}

func (s *SyncStateStore) Upsert(ctx context.Context, tx *sql.Tx, state *SyncState) error {
	var lastPush, lastPull *string
	if state.LastPushAt != nil {
		p := state.LastPushAt.UTC().Format(time.RFC3339)
		lastPush = &p
	}
	if state.LastPullAt != nil {
		p := state.LastPullAt.UTC().Format(time.RFC3339)
		lastPull = &p
	}

	_, err := tx.ExecContext(ctx,
		`INSERT INTO sync_state (id, environment_id, last_push_at, last_pull_at, remote_hash, local_hash)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			last_push_at = excluded.last_push_at,
			last_pull_at = excluded.last_pull_at,
			remote_hash = excluded.remote_hash,
			local_hash = excluded.local_hash`,
		state.ID, state.EnvironmentID, lastPush, lastPull, state.RemoteHash, state.LocalHash,
	)
	return err
}
