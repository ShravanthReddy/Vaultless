// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Shravanth. All rights reserved.

package models

import (
	"fmt"
	"regexp"
	"time"
)

const (
	MaxValueSize   = 1 << 20 // 1 MB
	MinPasswordLen = 8
)

// --- Data Models ---

type Secret struct {
	ID             string
	EnvironmentID  string
	KeyName        string
	EncryptedValue []byte
	Nonce          []byte
	Version        int
	CreatedAt      time.Time
	UpdatedAt      time.Time
	CreatedBy      string
	IsDeleted      bool
}

type SecretWithValue struct {
	Secret Secret
	Value  []byte
}

// Convenience accessors for SecretWithValue so callers
// don't need to reach through .Secret every time.
func (s *SecretWithValue) KeyName() string      { return s.Secret.KeyName }
func (s *SecretWithValue) Version() int          { return s.Secret.Version }
func (s *SecretWithValue) CreatedAt() time.Time  { return s.Secret.CreatedAt }
func (s *SecretWithValue) UpdatedAt() time.Time  { return s.Secret.UpdatedAt }

type SecretListEntry struct {
	KeyName     string
	Environment string
	Version     int
	UpdatedAt   time.Time
}

type SecretVersion struct {
	ID             string
	SecretID       string
	Version        int
	EncryptedValue []byte
	Nonce          []byte
	CreatedAt      time.Time
	CreatedBy      string
	ChangeType     string
}

type Environment struct {
	ID          string
	ProjectID   string
	Name        string
	CreatedAt   time.Time
	UpdatedAt   time.Time
	SecretCount int
}

type Project struct {
	ID        string
	Name      string
	CreatedAt time.Time
	UpdatedAt time.Time
}

type Token struct {
	ID         string
	Name       string
	HashedKey  []byte
	Permission string
	CreatedAt  time.Time
	ExpiresAt  *time.Time
	LastUsedAt *time.Time
	CreatedBy  string
	IsRevoked  bool
}

type TeamMember struct {
	ID        string
	Email     string
	Role      string
	InvitedBy string
	JoinedAt  *time.Time
	CreatedAt time.Time
	IsRemoved int
}

type AuditEntry struct {
	ID          string         `json:"id"`
	Timestamp   time.Time      `json:"timestamp"`
	Operation   string         `json:"operation"`
	User        string         `json:"user,omitempty"`
	Environment string         `json:"environment,omitempty"`
	Key         string         `json:"key,omitempty"`
	Success     bool           `json:"success"`
	Error       string         `json:"error,omitempty"`
	HMAC        string         `json:"hmac,omitempty"`
	Metadata    map[string]any `json:"metadata,omitempty"`
}

// DoctorCheck represents the result of a single health check.
type DoctorCheck struct {
	Name    string `json:"name"`
	Status  string `json:"status"`
	Message string `json:"message"`
}

// --- Config Models ---

type GlobalConfig struct {
	User struct {
		Name  string `toml:"name"`
		Email string `toml:"email"`
	} `toml:"user"`
	Defaults struct {
		Environment  string `toml:"environment"`
		OutputFormat string `toml:"output_format"`
	} `toml:"defaults"`
	Session struct {
		TTL string `toml:"ttl"`
	} `toml:"session"`
	UI struct {
		Color bool `toml:"color"`
	} `toml:"ui"`
}

type ProjectConfig struct {
	Version     int                `toml:"version"`
	Project     ProjectSection     `toml:"project"`
	Auth        AuthSection        `toml:"auth"`
	Environment EnvironmentSection `toml:"environment"`
	Sync        SyncSection        `toml:"sync"`
	Secrets     SecretsSection     `toml:"secrets"`
	Audit       AuditSection       `toml:"audit"`
}

type ProjectSection struct {
	ID        string `toml:"id"`
	Name      string `toml:"name"`
	CreatedAt string `toml:"created_at"`
}

type AuthSection struct {
	Method       string `toml:"method"`
	Salt         string `toml:"salt"`
	Verification string `toml:"verification"`
}

type EnvironmentSection struct {
	Active string `toml:"active"`
}

type SyncSection struct {
	Backend string `toml:"backend"`
	Remote  string `toml:"remote"`
	Branch  string `toml:"branch"`
}

type SecretsSection struct {
	MaxVersions  int `toml:"max_versions"`
	MaxValueSize int `toml:"max_value_size"`
}

type AuditSection struct {
	Enabled    bool `toml:"enabled"`
	MaxEntries int  `toml:"max_entries"`
}

// --- Validation ---

var (
	keyNameRe = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)
	envNameRe = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)
)

func ValidateKeyName(k string) error {
	if len(k) < 1 {
		return &ErrValidation{Field: "key_name", Message: "key name must not be empty"}
	}
	if !keyNameRe.MatchString(k) {
		return &ErrValidation{Field: "key_name", Message: fmt.Sprintf("key name %q must start with uppercase letter and contain only A-Z, 0-9, _", k)}
	}
	return nil
}

func ValidateEnvName(n string) error {
	if len(n) < 1 {
		return &ErrValidation{Field: "env_name", Message: "environment name must not be empty"}
	}
	if !envNameRe.MatchString(n) {
		return &ErrValidation{Field: "env_name", Message: fmt.Sprintf("environment name %q must start with lowercase letter and contain only a-z, 0-9, -", n)}
	}
	return nil
}

func ValidatePassword(p string) error {
	if len(p) < MinPasswordLen {
		return fmt.Errorf("password must be at least %d characters", MinPasswordLen)
	}
	return nil
}

func ValidateSecretValue(v []byte) error {
	if len(v) > MaxValueSize {
		return fmt.Errorf("secret value exceeds maximum size of %d bytes", MaxValueSize)
	}
	return nil
}

// --- Error Types ---

type ErrNotFound struct {
	Entity string
	Name   string
	Env    string
}

func (e *ErrNotFound) Error() string {
	if e.Env != "" {
		return fmt.Sprintf("%s %q not found in environment %q", e.Entity, e.Name, e.Env)
	}
	return fmt.Sprintf("%s %q not found", e.Entity, e.Name)
}

type ErrAlreadyExists struct {
	Entity string
	Name   string
}

func (e *ErrAlreadyExists) Error() string {
	return fmt.Sprintf("%s %q already exists", e.Entity, e.Name)
}

type ErrAuth struct {
	Msg string
}

func (e *ErrAuth) Error() string {
	return fmt.Sprintf("auth: %s", e.Msg)
}

type ErrValidation struct {
	Field   string
	Message string
}

func (e *ErrValidation) Error() string {
	return fmt.Sprintf("validation: %s: %s", e.Field, e.Message)
}

type ErrDatabase struct {
	Msg string
	Err error
}

func (e *ErrDatabase) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("database: %s: %v", e.Msg, e.Err)
	}
	return fmt.Sprintf("database: %s", e.Msg)
}

func (e *ErrDatabase) Unwrap() error {
	return e.Err
}

// ErrConflict is returned when a sync conflict is detected.
type ErrPermission struct {
	Action string
}

func (e *ErrPermission) Error() string {
	return fmt.Sprintf("permission denied: %s", e.Action)
}

// ErrConflict is returned when a sync conflict is detected.
type ErrConflict struct {
	LocalHash  string
	RemoteHash string
}

func (e *ErrConflict) Error() string {
	return fmt.Sprintf("conflict: local hash %q differs from remote hash %q; use --force to override", e.LocalHash, e.RemoteHash)
}
