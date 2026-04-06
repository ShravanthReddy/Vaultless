// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Shravanth. All rights reserved.

package db

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/vaultless/vaultless/internal/models"

	_ "modernc.org/sqlite"
)

var pragmas = []string{
	"PRAGMA journal_mode = WAL",
	"PRAGMA synchronous = NORMAL",
	"PRAGMA foreign_keys = ON",
	"PRAGMA busy_timeout = 5000",
	"PRAGMA cache_size = -2000",
	"PRAGMA auto_vacuum = INCREMENTAL",
	"PRAGMA temp_store = MEMORY",
}

// DB wraps the SQLite database connection.
type DB struct {
	conn *sql.DB
	path string
}

// Open opens the SQLite database and applies pragmas and migrations.
func Open(path string) (*DB, error) {
	conn, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, &models.ErrDatabase{Msg: "failed to open database", Err: err}
	}

	// SQLite is single-writer but WAL mode supports concurrent readers.
	// Allow 2 connections so reads can proceed while a transaction is active.
	conn.SetMaxOpenConns(2)

	db := &DB{conn: conn, path: path}

	if err := db.applyPragmas(); err != nil {
		conn.Close()
		return nil, err
	}

	if err := db.migrate(); err != nil {
		conn.Close()
		return nil, err
	}

	return db, nil
}

// Close closes the database connection.
func (db *DB) Close() error {
	_, _ = db.conn.Exec("PRAGMA wal_checkpoint(TRUNCATE)")
	return db.conn.Close()
}

// Conn returns the underlying sql.DB for direct access.
func (db *DB) Conn() *sql.DB {
	return db.conn
}

func (db *DB) applyPragmas() error {
	for _, pragma := range pragmas {
		if _, err := db.conn.Exec(pragma); err != nil {
			return &models.ErrDatabase{Msg: fmt.Sprintf("failed to apply pragma: %s", pragma), Err: err}
		}
	}
	return nil
}

// IntegrityCheck runs SQLite's built-in integrity check.
func (db *DB) IntegrityCheck(ctx context.Context) (string, error) {
	var result string
	err := db.conn.QueryRowContext(ctx, "PRAGMA integrity_check").Scan(&result)
	if err != nil {
		return "", &models.ErrDatabase{Msg: "integrity check failed", Err: err}
	}
	return result, nil
}

func (db *DB) migrate() error {
	_, err := db.conn.Exec(`
		CREATE TABLE IF NOT EXISTS _migrations (
			version    INTEGER PRIMARY KEY,
			applied_at TEXT NOT NULL
		)
	`)
	if err != nil {
		return &models.ErrDatabase{Msg: "failed to create migrations table", Err: err}
	}

	var current int
	row := db.conn.QueryRow("SELECT COALESCE(MAX(version), 0) FROM _migrations")
	if err := row.Scan(&current); err != nil {
		return &models.ErrDatabase{Msg: "failed to read migration version", Err: err}
	}

	for _, m := range migrations {
		if m.Version <= current {
			continue
		}

		if _, err := db.conn.Exec(m.SQL); err != nil {
			return &models.ErrDatabase{
				Msg: fmt.Sprintf("migration %d failed", m.Version),
				Err: err,
			}
		}

		_, err := db.conn.Exec(
			"INSERT INTO _migrations (version, applied_at) VALUES (?, ?)",
			m.Version, time.Now().UTC().Format(time.RFC3339),
		)
		if err != nil {
			return &models.ErrDatabase{Msg: "failed to record migration", Err: err}
		}
	}

	return nil
}
