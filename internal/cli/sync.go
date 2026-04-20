// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Shravanth. All rights reserved.

package cli

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
	"github.com/vaultless/vaultless/internal/models"
	"github.com/vaultless/vaultless/internal/output"
	"github.com/vaultless/vaultless/internal/service"
)

func newPushCmd(gf *GlobalFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "push",
		Short: "Push secrets to the sync backend",
		Example: `  vaultless push
  vaultless push --env prod
  vaultless push --force`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ac, err := initAppContext(gf)
			if err != nil {
				return err
			}
			defer ac.close()

			backend := newSyncBackend(ac.cfg)
			svc := service.NewSecretsService(ac.database, ac.cfg.ProjectID, ac.projectKey, ac.cfg.MaxVersions, ac.identity)
			syncSvc := service.NewSyncService(ac.database, svc, backend, ac.cfg.ProjectID)

			if err := syncSvc.Push(newContext(), ac.cfg.ActiveEnv, ac.cfg.Force); err != nil {
				return err
			}

			ac.audit.Log(&models.AuditEntry{
				Operation:   "push",
				User:        ac.identity,
				Environment: ac.cfg.ActiveEnv,
				Success:     true,
			})

			ac.formatter.Success("Pushed secrets for '%s'", ac.cfg.ActiveEnv)
			return nil
		},
	}
	return cmd
}

func newPullCmd(gf *GlobalFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "pull",
		Short: "Pull secrets from the sync backend",
		Example: `  vaultless pull
  vaultless pull --env staging
  vaultless pull --force`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ac, err := initAppContext(gf)
			if err != nil {
				return err
			}
			defer ac.close()

			backend := newSyncBackend(ac.cfg)
			svc := service.NewSecretsService(ac.database, ac.cfg.ProjectID, ac.projectKey, ac.cfg.MaxVersions, ac.identity)
			syncSvc := service.NewSyncService(ac.database, svc, backend, ac.cfg.ProjectID)

			if err := syncSvc.Pull(newContext(), ac.cfg.ActiveEnv, ac.cfg.Force); err != nil {
				return err
			}

			ac.audit.Log(&models.AuditEntry{
				Operation:   "pull",
				User:        ac.identity,
				Environment: ac.cfg.ActiveEnv,
				Success:     true,
			})

			ac.formatter.Success("Pulled secrets for '%s'", ac.cfg.ActiveEnv)
			return nil
		},
	}
	return cmd
}

func newStatusCmd(gf *GlobalFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show sync status",
		RunE: func(cmd *cobra.Command, args []string) error {
			ac, err := initAppContext(gf)
			if err != nil {
				return err
			}
			defer ac.close()

			backend := newSyncBackend(ac.cfg)
			svc := service.NewSecretsService(ac.database, ac.cfg.ProjectID, ac.projectKey, ac.cfg.MaxVersions, ac.identity)
			syncSvc := service.NewSyncService(ac.database, svc, backend, ac.cfg.ProjectID)

			status, err := syncSvc.Status(newContext())
			if err != nil {
				return err
			}

			if ac.cfg.OutputJSON {
				return ac.formatter.PrintJSON(status)
			}

			tbl := output.NewTable(os.Stdout, ac.formatter.NoColor, "PROPERTY", "VALUE")
			tbl.AddRow("Project", ac.cfg.ProjectName)
			tbl.AddRow("Active Environment", ac.cfg.ActiveEnv)
			tbl.AddRow("Sync Backend", status.Backend)
			if status.Remote != "" {
				tbl.AddRow("Remote", status.Remote)
			}
			if status.LastPushAt != nil {
				tbl.AddRow("Last Push", status.LastPushAt.Format(time.RFC3339))
			}
			if status.LastPullAt != nil {
				tbl.AddRow("Last Pull", status.LastPullAt.Format(time.RFC3339))
			}
			if status.HasLocalChanges {
				tbl.AddRow("Local Changes", "yes (not pushed)")
			}
			if status.HasRemoteChanges {
				tbl.AddRow("Remote Changes", "yes (not pulled)")
			}

			fmt.Printf("Project: %s\n", ac.cfg.ProjectName)
			return tbl.Flush()
		},
	}
}
