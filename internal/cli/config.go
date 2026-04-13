// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Shravanth. All rights reserved.

package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/vaultless/vaultless/internal/config"
	"github.com/vaultless/vaultless/internal/output"
)

func newConfigCmd(gf *GlobalFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Manage configuration",
	}

	cmd.AddCommand(
		newConfigGetCmd(gf),
		newConfigSetCmd(gf),
		newConfigListCmd(gf),
	)
	return cmd
}

func newConfigGetCmd(gf *GlobalFlags) *cobra.Command {
	return &cobra.Command{
		Use:     "get KEY",
		Short:   "Get a configuration value",
		Example: `  vaultless config get environment.active`,
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ac, err := initAppContext(gf)
			if err != nil {
				return err
			}
			defer ac.close()

			key := args[0]
			value := resolveConfigValue(ac.cfg, key)
			if value == "" {
				return fmt.Errorf("config key '%s' not found", key)
			}

			fmt.Println(value)
			return nil
		},
	}
}

func newConfigSetCmd(gf *GlobalFlags) *cobra.Command {
	var global bool

	cmd := &cobra.Command{
		Use:     "set KEY VALUE",
		Short:   "Set a configuration value",
		Example: `  vaultless config set environment.active staging`,
		Args:    cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			ac, err := initAppContext(gf)
			if err != nil {
				return err
			}
			defer ac.close()

			key, value := args[0], args[1]

			pc, err := config.LoadProjectConfig(ac.cfg.ProjectPath)
			if err != nil {
				return err
			}

			switch key {
			case "environment.active":
				pc.Environment.Active = value
			case "sync.backend":
				pc.Sync.Backend = value
			case "sync.remote":
				pc.Sync.Remote = value
			default:
				return fmt.Errorf("unknown config key: %s", key)
			}

			if err := config.SaveProjectConfig(ac.cfg.ProjectPath, pc); err != nil {
				return err
			}

			ac.formatter.Success("Config '%s' set to '%s'", key, value)
			return nil
		},
	}

	cmd.Flags().BoolVar(&global, "global", false, "Set in global config")
	return cmd
}

func newConfigListCmd(gf *GlobalFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List all configuration values",
		RunE: func(cmd *cobra.Command, args []string) error {
			ac, err := initAppContext(gf)
			if err != nil {
				return err
			}
			defer ac.close()

			tbl := output.NewTable(os.Stdout, ac.formatter.NoColor, "KEY", "VALUE", "SOURCE")
			tbl.AddRow("project.name", ac.cfg.ProjectName, "project")
			tbl.AddRow("project.id", ac.cfg.ProjectID, "project")
			tbl.AddRow("environment.active", ac.cfg.ActiveEnv, "resolved")
			tbl.AddRow("sync.backend", ac.cfg.SyncBackend, "project")
			tbl.AddRow("sync.remote", ac.cfg.SyncRemote, "project")
			tbl.AddRow("secrets.max_versions", fmt.Sprintf("%d", ac.cfg.MaxVersions), "project")
			tbl.AddRow("session.ttl", ac.cfg.SessionTTL.String(), "resolved")
			tbl.AddRow("user.name", ac.cfg.UserName, "global")
			tbl.AddRow("user.email", ac.cfg.UserEmail, "global")
			return tbl.Flush()
		},
	}
}

func resolveConfigValue(cfg *config.ResolvedConfig, key string) string {
	switch key {
	case "project.name":
		return cfg.ProjectName
	case "project.id":
		return cfg.ProjectID
	case "environment.active":
		return cfg.ActiveEnv
	case "sync.backend":
		return cfg.SyncBackend
	case "sync.remote":
		return cfg.SyncRemote
	case "user.name":
		return cfg.UserName
	case "user.email":
		return cfg.UserEmail
	default:
		return ""
	}
}
