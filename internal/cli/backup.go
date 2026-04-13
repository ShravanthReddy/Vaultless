// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Shravanth. All rights reserved.

package cli

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/vaultless/vaultless/internal/models"
	"github.com/vaultless/vaultless/internal/output"
	"github.com/vaultless/vaultless/internal/service"
)

func newBackupCmd(gf *GlobalFlags) *cobra.Command {
	var filePath string

	cmd := &cobra.Command{
		Use:   "backup",
		Short: "Backup the secrets database",
		Example: `  vaultless backup --file backup.vaultless
  vaultless backup`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ac, err := initAppContext(gf)
			if err != nil {
				return err
			}
			defer ac.close()

			if filePath == "" {
				filePath = fmt.Sprintf("%s-backup.vaultless", ac.cfg.ProjectName)
			}

			svc := service.NewBackupService(ac.cfg.ProjectPath, ac.cfg.ProjectID)
			if err := svc.Create(filePath); err != nil {
				return err
			}

			ac.audit.Log(&models.AuditEntry{
				Operation:   "backup",
				User:        ac.identity,
				Environment: ac.cfg.ActiveEnv,
				Success:     true,
				Metadata:    map[string]any{"file": filePath},
			})

			ac.formatter.Success("Backup created: %s", filePath)
			return nil
		},
	}

	cmd.Flags().StringVar(&filePath, "file", "", "Output file path")
	return cmd
}

func newRestoreCmd(gf *GlobalFlags) *cobra.Command {
	var filePath string

	cmd := &cobra.Command{
		Use:   "restore",
		Short: "Restore from a backup",
		Example: `  vaultless restore --file backup.vaultless`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ac, err := initAppContext(gf)
			if err != nil {
				return err
			}
			defer ac.close()

			if filePath == "" {
				return fmt.Errorf("--file is required")
			}

			if !ac.cfg.Force {
				confirmed, err := output.PromptConfirm("Restore will overwrite current secrets. Continue?")
				if err != nil || !confirmed {
					ac.formatter.Println("Aborted.")
					return nil
				}
			}

			// Close DB before restore
			ac.database.Close()
			ac.database = nil

			svc := service.NewBackupService(ac.cfg.ProjectPath, ac.cfg.ProjectID)
			if err := svc.Restore(filePath); err != nil {
				return err
			}

			ac.formatter.Success("Restored from backup: %s", filePath)
			return nil
		},
	}

	cmd.Flags().StringVar(&filePath, "file", "", "Backup file to restore from (required)")
	return cmd
}
