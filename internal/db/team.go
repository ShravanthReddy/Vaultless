// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Shravanth. All rights reserved.

package db

import (
	"context"
	"database/sql"
	"time"

	"github.com/vaultless/vaultless/internal/models"
)

// TeamStore handles team member CRUD operations.
type TeamStore struct {
	db *DB
}

func NewTeamStore(db *DB) *TeamStore {
	return &TeamStore{db: db}
}

func (s *TeamStore) Add(ctx context.Context, m *models.TeamMember) error {
	_, err := s.db.conn.ExecContext(ctx,
		`INSERT INTO team_members (id, email, role, invited_by, joined_at, created_at, is_removed)
		 VALUES (?, ?, ?, ?, ?, ?, 0)`,
		m.ID, m.Email, m.Role, m.InvitedBy, m.JoinedAt, m.CreatedAt.Format(time.RFC3339),
	)
	if err != nil {
		return &models.ErrDatabase{Msg: "failed to add team member", Err: err}
	}
	return nil
}

func (s *TeamStore) List(ctx context.Context) ([]models.TeamMember, error) {
	rows, err := s.db.conn.QueryContext(ctx,
		`SELECT id, email, role, invited_by, joined_at, created_at, is_removed
		 FROM team_members WHERE is_removed = 0
		 ORDER BY created_at`,
	)
	if err != nil {
		return nil, &models.ErrDatabase{Msg: "failed to list team members", Err: err}
	}
	defer rows.Close()

	var members []models.TeamMember
	for rows.Next() {
		var m models.TeamMember
		var createdAt string
		var joinedAt sql.NullString
		if err := rows.Scan(&m.ID, &m.Email, &m.Role, &m.InvitedBy, &joinedAt, &createdAt, &m.IsRemoved); err != nil {
			return nil, &models.ErrDatabase{Msg: "failed to scan team member", Err: err}
		}
		m.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
		if joinedAt.Valid {
			t, _ := time.Parse(time.RFC3339, joinedAt.String)
			m.JoinedAt = &t
		}
		members = append(members, m)
	}
	return members, rows.Err()
}

func (s *TeamStore) Remove(ctx context.Context, email string) error {
	result, err := s.db.conn.ExecContext(ctx,
		`UPDATE team_members SET is_removed = 1 WHERE email = ? AND is_removed = 0`,
		email,
	)
	if err != nil {
		return &models.ErrDatabase{Msg: "failed to remove team member", Err: err}
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return &models.ErrNotFound{Entity: "team member", Name: email}
	}
	return nil
}
