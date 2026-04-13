// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Shravanth. All rights reserved.

package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/vaultless/vaultless/internal/models"
	"github.com/vaultless/vaultless/internal/service"
)

func newImportCmd(gf *GlobalFlags) *cobra.Command {
	var format, prefix string
	var skipExisting bool

	cmd := &cobra.Command{
		Use:   "import FILE",
		Short: "Import secrets from a .env, JSON, or YAML file",
		Example: `  vaultless import .env
  vaultless import config.json --format json
  vaultless import secrets.yaml --format yaml --env staging
  vaultless import .env --prefix APP_`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ac, err := initAppContext(gf)
			if err != nil {
				return err
			}
			defer ac.close()

			filePath := args[0]
			f, err := os.Open(filePath)
			if err != nil {
				return fmt.Errorf("failed to open file: %w", err)
			}
			defer f.Close()

			var entries []service.EnvEntry
			switch format {
			case "json":
				entries, err = service.ParseJSONFile(f)
			case "yaml":
				entries, err = service.ParseYAMLFile(f)
			default:
				entries, err = service.ParseEnvFile(f)
			}
			if err != nil {
				return fmt.Errorf("failed to parse file: %w", err)
			}

			if prefix != "" {
				for i := range entries {
					entries[i].Key = prefix + entries[i].Key
				}
			}

			svc := service.NewSecretsService(ac.database, ac.cfg.ProjectID, ac.projectKey, ac.cfg.MaxVersions, ac.identity)

			var imported, skipped, overwritten int
			for _, entry := range entries {
				key := strings.ToUpper(entry.Key)
				if err := models.ValidateKeyName(key); err != nil {
					ac.formatter.Warn("Skipping invalid key '%s': %s", entry.Key, err)
					skipped++
					continue
				}

				existing, _ := svc.Get(newContext(), ac.cfg.ActiveEnv, key)
				if existing != nil {
					if skipExisting {
						skipped++
						continue
					}
					if !ac.cfg.Force {
						skipped++
						continue
					}
					overwritten++
				}

				_, err := svc.Set(newContext(), ac.cfg.ActiveEnv, key, []byte(entry.Value), true)
				if err != nil {
					ac.formatter.Warn("Failed to import '%s': %s", key, err)
					skipped++
					continue
				}
				imported++
			}

			ac.audit.Log(&models.AuditEntry{
				Operation:   "import",
				User:        ac.identity,
				Environment: ac.cfg.ActiveEnv,
				Success:     true,
				Metadata: map[string]any{
					"file":        filePath,
					"imported":    imported,
					"skipped":     skipped,
					"overwritten": overwritten,
				},
			})

			ac.formatter.Success("Imported %d secrets (%d skipped, %d overwritten) into '%s'",
				imported, skipped, overwritten, ac.cfg.ActiveEnv)
			return nil
		},
	}

	cmd.Flags().StringVar(&format, "format", "env", "Import format: env, json, yaml")
	cmd.Flags().StringVar(&prefix, "prefix", "", "Prefix to prepend to all imported keys")
	cmd.Flags().BoolVar(&skipExisting, "skip-existing", false, "Skip keys that already exist")

	return cmd
}
