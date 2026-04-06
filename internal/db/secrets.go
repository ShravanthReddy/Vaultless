// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Shravanth. All rights reserved.

package db

import (
	"context"
	"database/sql"
	"time"

	"github.com/vaultless/vaultless/internal/models"
)

// SecretStore handles secret CRUD + versioning operations.
type SecretStore struct {
	db *DB
}

func NewSecretStore(db *DB) *SecretStore {
	return &SecretStore{db: db}
}

func (s *SecretStore) GetByKey(ctx context.Context, envID, keyName string) (*models.Secret, error) {
	row := s.db.conn.QueryRowContext(ctx,
		`SELECT id, environment_id, key_name, encrypted_value, nonce, version,
			created_at, updated_at, created_by, is_deleted
		FROM secrets WHERE environment_id = ? AND key_name = ?`,
		envID, keyName,
	)

	return scanSecret(row)
}

func (s *SecretStore) Upsert(ctx context.Context, tx *sql.Tx, secret *models.Secret) error {
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := tx.ExecContext(ctx,
		`INSERT INTO secrets (id, environment_id, key_name, encrypted_value, nonce, version, created_at, updated_at, created_by, is_deleted)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(environment_id, key_name) DO UPDATE SET
			encrypted_value = excluded.encrypted_value,
			nonce = excluded.nonce,
			version = excluded.version,
			updated_at = excluded.updated_at,
			created_by = excluded.created_by,
			is_deleted = excluded.is_deleted`,
		secret.ID, secret.EnvironmentID, secret.KeyName, secret.EncryptedValue,
		secret.Nonce, secret.Version, now, now, secret.CreatedBy, boolToInt(secret.IsDeleted),
	)
	return err
}

func (s *SecretStore) SoftDelete(ctx context.Context, tx *sql.Tx, envID, keyName string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := tx.ExecContext(ctx,
		"UPDATE secrets SET is_deleted = 1, updated_at = ? WHERE environment_id = ? AND key_name = ? AND is_deleted = 0",
		now, envID, keyName,
	)
	return err
}

func (s *SecretStore) Purge(ctx context.Context, tx *sql.Tx, envID, keyName string) error {
	// Delete versions first
	_, err := tx.ExecContext(ctx,
		`DELETE FROM secret_versions WHERE secret_id IN
			(SELECT id FROM secrets WHERE environment_id = ? AND key_name = ?)`,
		envID, keyName,
	)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx,
		"DELETE FROM secrets WHERE environment_id = ? AND key_name = ?",
		envID, keyName,
	)
	return err
}

func (s *SecretStore) List(ctx context.Context, envID string) ([]models.SecretListEntry, error) {
	rows, err := s.db.conn.QueryContext(ctx,
		`SELECT s.key_name, e.name, s.version, s.updated_at
		FROM secrets s
		JOIN environments e ON e.id = s.environment_id
		WHERE s.environment_id = ? AND s.is_deleted = 0
		ORDER BY s.key_name`,
		envID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []models.SecretListEntry
	for rows.Next() {
		var entry models.SecretListEntry
		var updatedAt string
		if err := rows.Scan(&entry.KeyName, &entry.Environment, &entry.Version, &updatedAt); err != nil {
			return nil, err
		}
		entry.UpdatedAt, _ = time.Parse(time.RFC3339, updatedAt)
		entries = append(entries, entry)
	}
	return entries, rows.Err()
}

func (s *SecretStore) ListAll(ctx context.Context, envID string) ([]models.Secret, error) {
	rows, err := s.db.conn.QueryContext(ctx,
		`SELECT id, environment_id, key_name, encrypted_value, nonce, version,
			created_at, updated_at, created_by, is_deleted
		FROM secrets WHERE environment_id = ? AND is_deleted = 0
		ORDER BY key_name`,
		envID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var secrets []models.Secret
	for rows.Next() {
		var sec models.Secret
		var createdAt, updatedAt, createdBy string
		var isDeleted int
		if err := rows.Scan(&sec.ID, &sec.EnvironmentID, &sec.KeyName, &sec.EncryptedValue,
			&sec.Nonce, &sec.Version, &createdAt, &updatedAt, &createdBy, &isDeleted); err != nil {
			return nil, err
		}
		sec.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
		sec.UpdatedAt, _ = time.Parse(time.RFC3339, updatedAt)
		sec.CreatedBy = createdBy
		sec.IsDeleted = isDeleted != 0
		secrets = append(secrets, sec)
	}
	return secrets, rows.Err()
}

func (s *SecretStore) ListKeys(ctx context.Context, envID string) ([]string, error) {
	rows, err := s.db.conn.QueryContext(ctx,
		"SELECT key_name FROM secrets WHERE environment_id = ? AND is_deleted = 0 ORDER BY key_name",
		envID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var keys []string
	for rows.Next() {
		var key string
		if err := rows.Scan(&key); err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}
	return keys, rows.Err()
}

func (s *SecretStore) CopyAll(ctx context.Context, tx *sql.Tx, srcEnvID, dstEnvID string, genIDFunc func() string) error {
	rows, err := tx.QueryContext(ctx,
		`SELECT id, environment_id, key_name, encrypted_value, nonce, version,
			created_at, updated_at, created_by, is_deleted
		FROM secrets WHERE environment_id = ? AND is_deleted = 0
		ORDER BY key_name`,
		srcEnvID,
	)
	if err != nil {
		return err
	}
	defer rows.Close()

	var secrets []models.Secret
	for rows.Next() {
		var sec models.Secret
		var createdAt, updatedAt, createdBy string
		var isDeleted int
		if err := rows.Scan(&sec.ID, &sec.EnvironmentID, &sec.KeyName, &sec.EncryptedValue,
			&sec.Nonce, &sec.Version, &createdAt, &updatedAt, &createdBy, &isDeleted); err != nil {
			return err
		}
		sec.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
		sec.UpdatedAt, _ = time.Parse(time.RFC3339, updatedAt)
		sec.CreatedBy = createdBy
		sec.IsDeleted = isDeleted != 0
		secrets = append(secrets, sec)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if err != nil {
		return err
	}
	now := time.Now().UTC().Format(time.RFC3339)
	for _, sec := range secrets {
		newID := genIDFunc()
		_, err := tx.ExecContext(ctx,
			`INSERT INTO secrets (id, environment_id, key_name, encrypted_value, nonce, version, created_at, updated_at, created_by, is_deleted)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			newID, dstEnvID, sec.KeyName, sec.EncryptedValue, sec.Nonce,
			sec.Version, now, now, sec.CreatedBy, boolToInt(sec.IsDeleted),
		)
		if err != nil {
			return err
		}
	}
	return nil
}

// SecretVersionStore handles secret version operations.
type SecretVersionStore struct {
	db *DB
}

func NewSecretVersionStore(db *DB) *SecretVersionStore {
	return &SecretVersionStore{db: db}
}

func (s *SecretVersionStore) Create(ctx context.Context, tx *sql.Tx, v *models.SecretVersion) error {
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := tx.ExecContext(ctx,
		`INSERT INTO secret_versions (id, secret_id, version, encrypted_value, nonce, created_at, created_by, change_type)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		v.ID, v.SecretID, v.Version, v.EncryptedValue, v.Nonce, now, v.CreatedBy, v.ChangeType,
	)
	return err
}

func (s *SecretVersionStore) ListBySecretID(ctx context.Context, secretID string) ([]models.SecretVersion, error) {
	rows, err := s.db.conn.QueryContext(ctx,
		`SELECT id, secret_id, version, encrypted_value, nonce, created_at, created_by, change_type
		FROM secret_versions WHERE secret_id = ? ORDER BY version DESC`,
		secretID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var versions []models.SecretVersion
	for rows.Next() {
		var v models.SecretVersion
		var createdAt, createdBy string
		if err := rows.Scan(&v.ID, &v.SecretID, &v.Version, &v.EncryptedValue, &v.Nonce,
			&createdAt, &createdBy, &v.ChangeType); err != nil {
			return nil, err
		}
		v.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
		v.CreatedBy = createdBy
		versions = append(versions, v)
	}
	return versions, rows.Err()
}

func (s *SecretVersionStore) GetByVersion(ctx context.Context, secretID string, version int) (*models.SecretVersion, error) {
	row := s.db.conn.QueryRowContext(ctx,
		`SELECT id, secret_id, version, encrypted_value, nonce, created_at, created_by, change_type
		FROM secret_versions WHERE secret_id = ? AND version = ?`,
		secretID, version,
	)

	var v models.SecretVersion
	var createdAt, createdBy string
	if err := row.Scan(&v.ID, &v.SecretID, &v.Version, &v.EncryptedValue, &v.Nonce,
		&createdAt, &createdBy, &v.ChangeType); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	v.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	v.CreatedBy = createdBy
	return &v, nil
}

func (s *SecretVersionStore) PruneOldVersions(ctx context.Context, tx *sql.Tx, secretID string, maxVersions int) error {
	_, err := tx.ExecContext(ctx,
		`DELETE FROM secret_versions WHERE secret_id = ? AND version NOT IN
			(SELECT version FROM secret_versions WHERE secret_id = ? ORDER BY version DESC LIMIT ?)`,
		secretID, secretID, maxVersions,
	)
	return err
}

func scanSecret(row *sql.Row) (*models.Secret, error) {
	var s models.Secret
	var createdAt, updatedAt, createdBy string
	var isDeleted int
	if err := row.Scan(&s.ID, &s.EnvironmentID, &s.KeyName, &s.EncryptedValue,
		&s.Nonce, &s.Version, &createdAt, &updatedAt, &createdBy, &isDeleted); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	s.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	s.UpdatedAt, _ = time.Parse(time.RFC3339, updatedAt)
	s.CreatedBy = createdBy
	s.IsDeleted = isDeleted != 0
	return &s, nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
