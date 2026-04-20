// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Shravanth. All rights reserved.

package config

import (
	"os"
	"time"

	"github.com/vaultless/vaultless/internal/models"
)

// ResolvedConfig is the final merged configuration used by the application.
type ResolvedConfig struct {
	// Identity
	ProjectID   string
	ProjectName string
	ProjectPath string // Path to .vaultless/

	// Runtime
	ActiveEnv string
	OutputJSON bool
	Quiet      bool
	Force      bool
	NoColor    bool
	Verbose    bool

	// Auth
	Token    string // From VAULTLESS_TOKEN
	AuthConf models.AuthSection

	// Sync
	SyncBackend string
	SyncRemote  string
	SyncBranch  string

	// Limits
	MaxVersions  int
	MaxValueSize int

	// Session
	SessionTTL time.Duration

	// User
	UserName  string
	UserEmail string

	// Audit
	AuditEnabled    bool
	AuditMaxEntries int
}

// GlobalFlags mirrors the CLI global flags for config resolution.
type GlobalFlags struct {
	Env     string
	JSON    bool
	Quiet   bool
	Force   bool
	NoColor bool
	Verbose bool
}

// Load resolves the full configuration from all sources.
func Load(flags *GlobalFlags) (*ResolvedConfig, error) {
	cfg := &ResolvedConfig{}

	// 1. Apply built-in defaults
	applyDefaults(cfg)
	cfg.AuditEnabled = true

	// 2. Load and merge global config
	mergeGlobalConfig(cfg)

	// 3. Load and merge project config
	mergeProjectConfig(cfg)

	// 4. Apply environment variables
	applyEnvVars(cfg)

	// 5. Apply command-line flags
	if flags != nil {
		applyFlags(cfg, flags)
	}

	return cfg, nil
}

func applyEnvVars(cfg *ResolvedConfig) {
	if env := os.Getenv("VAULTLESS_ENV"); env != "" {
		cfg.ActiveEnv = env
	}
	if token := os.Getenv("VAULTLESS_TOKEN"); token != "" {
		cfg.Token = token
	}
	if os.Getenv("VAULTLESS_NO_COLOR") != "" || os.Getenv("NO_COLOR") != "" {
		cfg.NoColor = true
	}
	if os.Getenv("VAULTLESS_QUIET") != "" {
		cfg.Quiet = true
	}
}

func applyFlags(cfg *ResolvedConfig, flags *GlobalFlags) {
	if flags.Env != "" {
		cfg.ActiveEnv = flags.Env
	}
	if flags.JSON {
		cfg.OutputJSON = true
	}
	if flags.Quiet {
		cfg.Quiet = true
	}
	if flags.Force {
		cfg.Force = true
	}
	if flags.NoColor {
		cfg.NoColor = true
	}
	if flags.Verbose {
		cfg.Verbose = true
	}
}
