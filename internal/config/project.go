// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Shravanth. All rights reserved.

package config

import (
	"os"
	"path/filepath"

	"github.com/vaultless/vaultless/internal/models"
)

const VaultlessDir = ".vaultless"

// DiscoverProject walks up the directory tree from the current working directory
// looking for a .vaultless/ directory.
func DiscoverProject() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}

	for {
		candidate := filepath.Join(dir, VaultlessDir)
		if info, err := os.Stat(candidate); err == nil && info.IsDir() {
			return candidate, nil
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			return "", &models.ErrNotFound{
				Entity: "project",
				Name:   "Not a vaultless project (or any parent up to root). Run 'vaultless init' to create one.",
			}
		}
		dir = parent
	}
}

// GlobalDir returns the path to the global config directory (~/.vaultless/).
func GlobalDir() string {
	if home := os.Getenv("VAULTLESS_HOME"); home != "" {
		return home
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".vaultless")
}
