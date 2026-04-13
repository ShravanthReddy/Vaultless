// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Shravanth. All rights reserved.

package cli

import (
	"os"

	"github.com/spf13/cobra"
	"github.com/vaultless/vaultless/internal/models"
	"github.com/vaultless/vaultless/internal/service"
)

func newExportCmd(gf *GlobalFlags) *cobra.Command {
	var filePath, format, filter, exclude string

	cmd := &cobra.Command{
		Use:   "export",
		Short: "Export secrets to .env, JSON, or YAML format",
		Example: `  vaultless export
  vaultless export --env prod --file .env.prod
  vaultless export --format json
  vaultless export --filter "DB_*"`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ac, err := initAppContext(gf)
			if err != nil {
				return err
			}
			defer ac.close()

			svc := service.NewSecretsService(ac.database, ac.cfg.ProjectID, ac.projectKey, ac.cfg.MaxVersions, ac.identity)
			secrets, err := svc.ListDecrypted(newContext(), ac.cfg.ActiveEnv)
			if err != nil {
				return err
			}

			opts := &service.ExportOptions{
				Format:  service.ExportFormat(format),
				Filter:  filter,
				Exclude: exclude,
			}

			var w *os.File
			if filePath != "" {
				w, err = os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
				if err != nil {
					return err
				}
				defer w.Close()
			} else {
				w = os.Stdout
			}

			if err := service.Export(w, secrets, ac.cfg.ActiveEnv, opts); err != nil {
				return err
			}

			ac.audit.Log(&models.AuditEntry{
				Operation:   "export",
				User:        ac.identity,
				Environment: ac.cfg.ActiveEnv,
				Success:     true,
				Metadata: map[string]any{
					"format": format,
					"count":  len(secrets),
				},
			})

			if filePath != "" {
				ac.formatter.Success("Exported %d secrets to %s", len(secrets), filePath)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&filePath, "file", "", "Write to file instead of stdout")
	cmd.Flags().StringVar(&format, "format", "env", "Output format: env, json, yaml")
	cmd.Flags().StringVar(&filter, "filter", "", "Only export secrets matching glob pattern")
	cmd.Flags().StringVar(&exclude, "exclude", "", "Exclude secrets matching glob pattern")

	return cmd
}
