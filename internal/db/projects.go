// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Shravanth. All rights reserved.

package db

import (
	"context"
	"database/sql"
	"time"

	"github.com/vaultless/vaultless/internal/models"
)

// ProjectStore handles project CRUD operations.
type ProjectStore struct {
	db *DB
}

func NewProjectStore(db *DB) *ProjectStore {
	return &ProjectStore{db: db}
}

func (s *ProjectStore) Create(ctx context.Context, tx *sql.Tx, project *models.Project) error {
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := tx.ExecContext(ctx,
		"INSERT INTO projects (id, name, created_at, updated_at) VALUES (?, ?, ?, ?)",
		project.ID, project.Name, now, now,
	)
	return err
}

func (s *ProjectStore) GetByID(ctx context.Context, id string) (*models.Project, error) {
	row := s.db.conn.QueryRowContext(ctx,
		"SELECT id, name, created_at, updated_at FROM projects WHERE id = ?", id,
	)

	var p models.Project
	var createdAt, updatedAt string
	if err := row.Scan(&p.ID, &p.Name, &createdAt, &updatedAt); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	p.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	p.UpdatedAt, _ = time.Parse(time.RFC3339, updatedAt)
	return &p, nil
}
