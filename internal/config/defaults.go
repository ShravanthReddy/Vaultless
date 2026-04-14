// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Shravanth. All rights reserved.

package config

import "time"

func applyDefaults(cfg *ResolvedConfig) {
	cfg.ActiveEnv = "dev"
	cfg.OutputJSON = false
	cfg.Quiet = false
	cfg.Force = false
	cfg.NoColor = false
	cfg.Verbose = false
	cfg.SyncBackend = "none"
	cfg.SyncBranch = "main"
	cfg.MaxVersions = 50
	cfg.MaxValueSize = 1 << 20 // 1 MB
	cfg.SessionTTL = 24 * time.Hour
}
