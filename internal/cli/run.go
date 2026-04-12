// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Shravanth. All rights reserved.

package cli

import (
	"github.com/spf13/cobra"
	"github.com/vaultless/vaultless/internal/models"
	"github.com/vaultless/vaultless/internal/service"
	"os"
)

func newRunCmd(gf *GlobalFlags) *cobra.Command {
	var only, exclude string
	var noOverride, dotenv, watch bool

	cmd := &cobra.Command{
		Use:   "run -- COMMAND [ARGS...]",
		Short: "Run a command with secrets injected as environment variables",
		Long:  `Execute a command with all secrets from the active environment injected as environment variables.`,
		Example: `  vaultless run -- npm start
  vaultless run --env prod -- ./deploy.sh
  vaultless run --only "DB_*" -- node server.js
  vaultless run --dotenv -- docker-compose up`,
		DisableFlagParsing: false,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return &models.ErrValidation{Field: "command", Message: "no command specified. Usage: vaultless run -- <command>"}
			}

			ac, err := initAppContext(gf)
			if err != nil {
				return err
			}
			defer ac.close()

			svc := service.NewSecretsService(ac.database, ac.cfg.ProjectID, ac.projectKey, ac.cfg.MaxVersions, ac.identity)
			runner := service.NewRunner(svc)

			opts := &service.RunOptions{
				Command:    args[0],
				Args:       args[1:],
				Env:        ac.cfg.ActiveEnv,
				Only:       only,
				Exclude:    exclude,
				NoOverride: noOverride,
				DotEnv:     dotenv,
				Watch:      watch,
			}

			ac.audit.Log(&models.AuditEntry{
				Operation:   "run",
				User:        ac.identity,
				Environment: ac.cfg.ActiveEnv,
				Success:     true,
				Metadata:    map[string]any{"command": opts.Command},
			})

			exitCode, err := runner.Exec(newContext(), opts)
			if err != nil {
				return err
			}
			os.Exit(exitCode)
			return nil
		},
	}

	cmd.Flags().StringVar(&only, "only", "", "Only inject secrets matching glob pattern")
	cmd.Flags().StringVar(&exclude, "exclude", "", "Exclude secrets matching glob pattern")
	cmd.Flags().BoolVar(&noOverride, "no-override", false, "Existing env vars take precedence")
	cmd.Flags().BoolVar(&dotenv, "dotenv", false, "Write secrets to temp .env file")
	cmd.Flags().BoolVar(&watch, "watch", false, "Restart on secret change")

	return cmd
}
