// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Shravanth. All rights reserved.

package db

import (
	"context"
	"database/sql"
	"time"

	"github.com/vaultless/vaultless/internal/models"
)

// EnvironmentStore handles environment CRUD operations.
type EnvironmentStore struct {
	db *DB
}

func NewEnvironmentStore(db *DB) *EnvironmentStore {
	return &EnvironmentStore{db: db}
}

func (s *EnvironmentStore) Create(ctx context.Context, tx *sql.Tx, env *models.Environment) error {
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := tx.ExecContext(ctx,
		"INSERT INTO environments (id, project_id, name, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
		env.ID, env.ProjectID, env.Name, now, now,
	)
	return err
}

func (s *EnvironmentStore) GetByName(ctx context.Context, projectID, name string) (*models.Environment, error) {
	row := s.db.conn.QueryRowContext(ctx,
		"SELECT id, project_id, name, created_at, updated_at FROM environments WHERE project_id = ? AND name = ?",
		projectID, name,
	)

	var env models.Environment
	var createdAt, updatedAt string
	if err := row.Scan(&env.ID, &env.ProjectID, &env.Name, &createdAt, &updatedAt); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	env.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	env.UpdatedAt, _ = time.Parse(time.RFC3339, updatedAt)
	return &env, nil
}

func (s *EnvironmentStore) List(ctx context.Context, projectID string) ([]models.Environment, error) {
	rows, err := s.db.conn.QueryContext(ctx,
		`SELECT e.id, e.project_id, e.name, e.created_at, e.updated_at,
			COALESCE((SELECT COUNT(*) FROM secrets s WHERE s.environment_id = e.id AND s.is_deleted = 0), 0) as secret_count
		FROM environments e WHERE e.project_id = ? ORDER BY e.name`,
		projectID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var envs []models.Environment
	for rows.Next() {
		var env models.Environment
		var createdAt, updatedAt string
		if err := rows.Scan(&env.ID, &env.ProjectID, &env.Name, &createdAt, &updatedAt, &env.SecretCount); err != nil {
			return nil, err
		}
		env.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
		env.UpdatedAt, _ = time.Parse(time.RFC3339, updatedAt)
		envs = append(envs, env)
	}
	return envs, rows.Err()
}

func (s *EnvironmentStore) Delete(ctx context.Context, tx *sql.Tx, envID string) error {
	// Delete secrets and versions first
	_, err := tx.ExecContext(ctx,
		"DELETE FROM secret_versions WHERE secret_id IN (SELECT id FROM secrets WHERE environment_id = ?)", envID)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, "DELETE FROM secrets WHERE environment_id = ?", envID)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, "DELETE FROM sync_state WHERE environment_id = ?", envID)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, "DELETE FROM environments WHERE id = ?", envID)
	return err
}

func (s *EnvironmentStore) ListNames(ctx context.Context, projectID string) ([]string, error) {
	rows, err := s.db.conn.QueryContext(ctx,
		"SELECT name FROM environments WHERE project_id = ? ORDER BY name", projectID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		names = append(names, name)
	}
	return names, rows.Err()
}
