// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Shravanth. All rights reserved.

package config

import (
	"os"
	"path/filepath"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/vaultless/vaultless/internal/models"
)

func mergeGlobalConfig(cfg *ResolvedConfig) {
	globalPath := filepath.Join(GlobalDir(), "config.toml")
	data, err := os.ReadFile(globalPath)
	if err != nil {
		return // No global config is fine
	}

	var gc models.GlobalConfig
	if err := toml.Unmarshal(data, &gc); err != nil {
		return
	}

	if gc.User.Name != "" {
		cfg.UserName = gc.User.Name
	}
	if gc.User.Email != "" {
		cfg.UserEmail = gc.User.Email
	}
	if gc.Defaults.Environment != "" {
		cfg.ActiveEnv = gc.Defaults.Environment
	}
	if gc.Defaults.OutputFormat == "json" {
		cfg.OutputJSON = true
	}
	if gc.Session.TTL != "" {
		if d, err := time.ParseDuration(gc.Session.TTL); err == nil {
			cfg.SessionTTL = d
		}
	}
	cfg.NoColor = !gc.UI.Color
}

func mergeProjectConfig(cfg *ResolvedConfig) {
	projectPath, err := DiscoverProject()
	if err != nil {
		return // No project found is fine for some commands
	}

	cfg.ProjectPath = projectPath
	configPath := filepath.Join(projectPath, "config.toml")
	data, err := os.ReadFile(configPath)
	if err != nil {
		return
	}

	var pc models.ProjectConfig
	if err := toml.Unmarshal(data, &pc); err != nil {
		return
	}

	cfg.ProjectID = pc.Project.ID
	cfg.ProjectName = pc.Project.Name
	cfg.AuthConf = pc.Auth

	if pc.Environment.Active != "" {
		cfg.ActiveEnv = pc.Environment.Active
	}
	if pc.Sync.Backend != "" {
		cfg.SyncBackend = pc.Sync.Backend
	}
	if pc.Sync.Remote != "" {
		cfg.SyncRemote = pc.Sync.Remote
	}
	if pc.Sync.Branch != "" {
		cfg.SyncBranch = pc.Sync.Branch
	}
	if pc.Secrets.MaxVersions > 0 {
		cfg.MaxVersions = pc.Secrets.MaxVersions
	}
	if pc.Secrets.MaxValueSize > 0 {
		cfg.MaxValueSize = pc.Secrets.MaxValueSize
	}
	cfg.AuditEnabled = pc.Audit.Enabled
}

// SaveProjectConfig writes the project config to .vaultless/config.toml.
func SaveProjectConfig(projectPath string, pc *models.ProjectConfig) error {
	configPath := filepath.Join(projectPath, "config.toml")
	f, err := os.Create(configPath)
	if err != nil {
		return err
	}
	defer f.Close()

	enc := toml.NewEncoder(f)
	return enc.Encode(pc)
}

// LoadProjectConfig reads the project config from .vaultless/config.toml.
func LoadProjectConfig(projectPath string) (*models.ProjectConfig, error) {
	configPath := filepath.Join(projectPath, "config.toml")
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, err
	}

	var pc models.ProjectConfig
	if err := toml.Unmarshal(data, &pc); err != nil {
		return nil, err
	}
	return &pc, nil
}
