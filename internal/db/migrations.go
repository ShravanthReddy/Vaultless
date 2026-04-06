// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Shravanth. All rights reserved.

package db

var migrations = []struct {
	Version int
	SQL     string
}{
	{
		Version: 1,
		SQL: `
			CREATE TABLE projects (
				id          TEXT PRIMARY KEY,
				name        TEXT NOT NULL,
				created_at  TEXT NOT NULL,
				updated_at  TEXT NOT NULL
			);

			CREATE TABLE environments (
				id          TEXT PRIMARY KEY,
				project_id  TEXT NOT NULL REFERENCES projects(id),
				name        TEXT NOT NULL,
				created_at  TEXT NOT NULL,
				updated_at  TEXT NOT NULL,
				UNIQUE(project_id, name)
			);

			CREATE TABLE secrets (
				id              TEXT PRIMARY KEY,
				environment_id  TEXT NOT NULL REFERENCES environments(id),
				key_name        TEXT NOT NULL,
				encrypted_value BLOB NOT NULL,
				nonce           BLOB NOT NULL,
				version         INTEGER NOT NULL DEFAULT 1,
				created_at      TEXT NOT NULL,
				updated_at      TEXT NOT NULL,
				created_by      TEXT,
				is_deleted      INTEGER NOT NULL DEFAULT 0,
				UNIQUE(environment_id, key_name)
			);

			CREATE TABLE secret_versions (
				id              TEXT PRIMARY KEY,
				secret_id       TEXT NOT NULL REFERENCES secrets(id),
				version         INTEGER NOT NULL,
				encrypted_value BLOB NOT NULL,
				nonce           BLOB NOT NULL,
				created_at      TEXT NOT NULL,
				created_by      TEXT,
				change_type     TEXT NOT NULL,
				UNIQUE(secret_id, version)
			);

			CREATE TABLE sync_state (
				id              TEXT PRIMARY KEY,
				environment_id  TEXT NOT NULL REFERENCES environments(id),
				last_push_at    TEXT,
				last_pull_at    TEXT,
				remote_hash     TEXT,
				local_hash      TEXT
			);

			CREATE TABLE tokens (
				id          TEXT PRIMARY KEY,
				name        TEXT NOT NULL UNIQUE,
				hashed_key  BLOB NOT NULL,
				permission  TEXT NOT NULL DEFAULT 'read-only',
				created_at  TEXT NOT NULL,
				expires_at  TEXT,
				last_used_at TEXT,
				created_by  TEXT,
				is_revoked  INTEGER NOT NULL DEFAULT 0
			);

			CREATE INDEX idx_secrets_env_key ON secrets(environment_id, key_name);
			CREATE INDEX idx_secrets_env ON secrets(environment_id);
			CREATE INDEX idx_secret_versions_secret ON secret_versions(secret_id);
			CREATE INDEX idx_environments_project ON environments(project_id);
			CREATE INDEX idx_tokens_name ON tokens(name);
		`,
	},
	{
		Version: 2,
		SQL: `
			CREATE TABLE team_members (
				id          TEXT PRIMARY KEY,
				email       TEXT NOT NULL,
				role        TEXT NOT NULL DEFAULT 'member',
				invited_by  TEXT,
				joined_at   TEXT,
				created_at  TEXT NOT NULL,
				is_removed  INTEGER NOT NULL DEFAULT 0,
				UNIQUE(email)
			);

			CREATE INDEX idx_team_members_email ON team_members(email);
		`,
	},
}
