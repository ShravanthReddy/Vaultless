// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Shravanth. All rights reserved.

package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
	"github.com/vaultless/vaultless/internal/models"
	"github.com/vaultless/vaultless/internal/output"
	"github.com/vaultless/vaultless/internal/service"
)

func newSetCmd(gf *GlobalFlags) *cobra.Command {
	var filePath string

	cmd := &cobra.Command{
		Use:   "set KEY [VALUE]",
		Short: "Set a secret in the active environment",
		Long:  `Set a secret. If VALUE is omitted, you will be prompted for secure input.`,
		Example: `  vaultless set DATABASE_URL postgres://localhost/mydb
  vaultless set API_KEY                         # prompts for value
  vaultless set TLS_CERT --file ./cert.pem
  vaultless set DATABASE_URL value --env prod`,
		Args: cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			ac, err := initAppContext(gf)
			if err != nil {
				return err
			}
			defer ac.close()

			keyName := args[0]
			var value []byte

			if filePath != "" {
				value, err = os.ReadFile(filePath)
				if err != nil {
					return fmt.Errorf("failed to read file: %w", err)
				}
			} else if len(args) >= 2 {
				value = []byte(args[1])
			} else {
				pw, err := output.PromptPassword(fmt.Sprintf("Value for %s", keyName))
				if err != nil {
					return err
				}
				value = []byte(pw)
			}

			svc := service.NewSecretsService(ac.database, ac.cfg.ProjectID, ac.projectKey, ac.cfg.MaxVersions, ac.identity)

			// Check for existing (unless force)
			if !ac.cfg.Force {
				existing, _ := svc.Get(newContext(), ac.cfg.ActiveEnv, keyName)
				if existing != nil {
					confirmed, err := output.PromptConfirm(fmt.Sprintf("Secret '%s' already exists (v%d). Overwrite?", keyName, existing.Version))
					if err != nil || !confirmed {
						ac.formatter.Println("Aborted.")
						return nil
					}
				}
			}

			version, err := svc.Set(newContext(), ac.cfg.ActiveEnv, keyName, value, ac.cfg.Force)
			if err != nil {
				return err
			}

			ac.audit.Log(&models.AuditEntry{
				Operation:   "set",
				User:        ac.identity,
				Environment: ac.cfg.ActiveEnv,
				Key:         keyName,
				Success:     true,
				Metadata:    map[string]any{"version": version},
			})

			ac.formatter.Success("Secret '%s' set in '%s' (v%d)", keyName, ac.cfg.ActiveEnv, version)
			return nil
		},
	}

	cmd.Flags().StringVar(&filePath, "file", "", "Read secret value from file")
	return cmd
}

func newGetCmd(gf *GlobalFlags) *cobra.Command {
	var version int

	cmd := &cobra.Command{
		Use:   "get KEY",
		Short: "Get a secret from the active environment",
		Example: `  vaultless get DATABASE_URL
  vaultless get API_KEY --env prod
  vaultless get API_KEY --json
  vaultless get API_KEY --version 2`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ac, err := initAppContext(gf)
			if err != nil {
				return err
			}
			defer ac.close()

			keyName := args[0]
			svc := service.NewSecretsService(ac.database, ac.cfg.ProjectID, ac.projectKey, ac.cfg.MaxVersions, ac.identity)

			var result *models.SecretWithValue
			if version > 0 {
				result, err = svc.GetVersion(newContext(), ac.cfg.ActiveEnv, keyName, version)
			} else {
				result, err = svc.Get(newContext(), ac.cfg.ActiveEnv, keyName)
			}
			if err != nil {
				return err
			}

			ac.audit.Log(&models.AuditEntry{
				Operation:   "get",
				User:        ac.identity,
				Environment: ac.cfg.ActiveEnv,
				Key:         keyName,
				Success:     true,
			})

			if ac.cfg.OutputJSON {
				out := map[string]any{
					"key":         result.KeyName,
					"value":       string(result.Value),
					"environment": ac.cfg.ActiveEnv,
					"created_at":  result.CreatedAt.Format(time.RFC3339),
					"updated_at":  result.UpdatedAt.Format(time.RFC3339),
					"version":     result.Version,
				}
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(out)
			}

			ac.formatter.PrintResult(string(result.Value))
			if ac.formatter.IsTTY {
				fmt.Println()
			}
			return nil
		},
	}

	cmd.Flags().IntVar(&version, "version", 0, "Retrieve a specific version")
	return cmd
}

func newDeleteCmd(gf *GlobalFlags) *cobra.Command {
	var allEnvs bool
	var purge bool

	cmd := &cobra.Command{
		Use:   "delete KEY",
		Short: "Delete a secret from the active environment",
		Example: `  vaultless delete API_KEY
  vaultless delete API_KEY --all-envs
  vaultless delete --purge API_KEY`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ac, err := initAppContext(gf)
			if err != nil {
				return err
			}
			defer ac.close()

			keyName := args[0]

			if !ac.cfg.Force {
				msg := fmt.Sprintf("Delete secret '%s'?", keyName)
				if purge {
					msg = fmt.Sprintf("Permanently delete secret '%s' and all versions?", keyName)
				}
				confirmed, err := output.PromptConfirm(msg)
				if err != nil || !confirmed {
					ac.formatter.Println("Aborted.")
					return nil
				}
			}

			svc := service.NewSecretsService(ac.database, ac.cfg.ProjectID, ac.projectKey, ac.cfg.MaxVersions, ac.identity)

			if allEnvs {
				if err := svc.DeleteAllEnvs(newContext(), keyName); err != nil {
					return err
				}
			} else {
				if err := svc.Delete(newContext(), ac.cfg.ActiveEnv, keyName, purge); err != nil {
					return err
				}
			}

			ac.audit.Log(&models.AuditEntry{
				Operation:   "delete",
				User:        ac.identity,
				Environment: ac.cfg.ActiveEnv,
				Key:         keyName,
				Success:     true,
				Metadata:    map[string]any{"purge": purge, "all_envs": allEnvs},
			})

			if purge {
				ac.formatter.Success("Secret '%s' permanently deleted", keyName)
			} else {
				ac.formatter.Success("Secret '%s' deleted from '%s'", keyName, ac.cfg.ActiveEnv)
			}
			return nil
		},
	}

	cmd.Flags().BoolVar(&allEnvs, "all-envs", false, "Delete from all environments")
	cmd.Flags().BoolVar(&purge, "purge", false, "Permanently delete including all versions")
	return cmd
}

func newListCmd(gf *GlobalFlags) *cobra.Command {
	var allEnvs bool
	var filter string

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List all secrets in the active environment",
		Example: `  vaultless list
  vaultless list --env prod
  vaultless list --all-envs
  vaultless list --filter "DB_*"
  vaultless list --json`,
		Aliases: []string{"ls"},
		RunE: func(cmd *cobra.Command, args []string) error {
			ac, err := initAppContext(gf)
			if err != nil {
				return err
			}
			defer ac.close()

			svc := service.NewSecretsService(ac.database, ac.cfg.ProjectID, ac.projectKey, ac.cfg.MaxVersions, ac.identity)

			if allEnvs {
				allEntries, err := svc.ListAllEnvs(newContext())
				if err != nil {
					return err
				}

				if ac.cfg.OutputJSON {
					return ac.formatter.PrintJSON(allEntries)
				}

				for envName, entries := range allEntries {
					fmt.Printf("\nEnvironment: %s\n", envName)
					printSecretList(ac.formatter, entries, filter)
				}
				return nil
			}

			entries, err := svc.List(newContext(), ac.cfg.ActiveEnv)
			if err != nil {
				return err
			}

			ac.audit.Log(&models.AuditEntry{
				Operation:   "list",
				User:        ac.identity,
				Environment: ac.cfg.ActiveEnv,
				Success:     true,
				Metadata:    map[string]any{"count": len(entries)},
			})

			if ac.cfg.OutputJSON {
				return ac.formatter.PrintJSON(entries)
			}

			printSecretList(ac.formatter, entries, filter)
			return nil
		},
	}

	cmd.Flags().BoolVar(&allEnvs, "all-envs", false, "List secrets across all environments")
	cmd.Flags().StringVar(&filter, "filter", "", "Glob pattern to filter keys")
	return cmd
}

func printSecretList(f *output.Formatter, entries []models.SecretListEntry, filter string) {
	if len(entries) == 0 {
		f.Println("No secrets found.")
		return
	}

	tbl := output.NewTable(os.Stdout, f.NoColor, "KEY", "ENVIRONMENT", "VERSION", "UPDATED")
	for _, e := range entries {
		if filter != "" {
			matched, _ := matchGlob(filter, e.KeyName)
			if !matched {
				continue
			}
		}
		tbl.AddRow(e.KeyName, e.Environment, fmt.Sprintf("v%d", e.Version), e.UpdatedAt.Format("2006-01-02 15:04:05"))
	}
	tbl.Flush()
}

func newHistoryCmd(gf *GlobalFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "history KEY",
		Short:   "Show version history of a secret",
		Example: `  vaultless history API_KEY`,
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ac, err := initAppContext(gf)
			if err != nil {
				return err
			}
			defer ac.close()

			keyName := args[0]
			svc := service.NewSecretsService(ac.database, ac.cfg.ProjectID, ac.projectKey, ac.cfg.MaxVersions, ac.identity)

			versions, err := svc.History(newContext(), ac.cfg.ActiveEnv, keyName)
			if err != nil {
				return err
			}

			if ac.cfg.OutputJSON {
				return ac.formatter.PrintJSON(versions)
			}

			tbl := output.NewTable(os.Stdout, ac.formatter.NoColor, "VERSION", "CHANGE", "BY", "DATE")
			for _, v := range versions {
				tbl.AddRow(
					fmt.Sprintf("v%d", v.Version),
					v.ChangeType,
					v.CreatedBy,
					v.CreatedAt.Format("2006-01-02 15:04:05"),
				)
			}
			return tbl.Flush()
		},
	}
	return cmd
}

func newRollbackCmd(gf *GlobalFlags) *cobra.Command {
	var version int

	cmd := &cobra.Command{
		Use:     "rollback KEY",
		Short:   "Restore a previous version of a secret",
		Example: `  vaultless rollback API_KEY --version 2`,
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ac, err := initAppContext(gf)
			if err != nil {
				return err
			}
			defer ac.close()

			if version == 0 {
				return fmt.Errorf("--version is required")
			}

			keyName := args[0]
			svc := service.NewSecretsService(ac.database, ac.cfg.ProjectID, ac.projectKey, ac.cfg.MaxVersions, ac.identity)

			if err := svc.Rollback(newContext(), ac.cfg.ActiveEnv, keyName, version); err != nil {
				return err
			}

			ac.audit.Log(&models.AuditEntry{
				Operation:   "rollback",
				User:        ac.identity,
				Environment: ac.cfg.ActiveEnv,
				Key:         keyName,
				Success:     true,
				Metadata:    map[string]any{"to_version": version},
			})

			ac.formatter.Success("Secret '%s' rolled back to v%d", keyName, version)
			return nil
		},
	}

	cmd.Flags().IntVar(&version, "version", 0, "Version to restore")
	return cmd
}

// matchGlob is a simple glob matcher supporting * and ? wildcards.
func matchGlob(pattern, s string) (bool, error) {
	return matchGlobRecursive(pattern, s), nil
}

func matchGlobRecursive(pattern, s string) bool {
	for len(pattern) > 0 {
		switch pattern[0] {
		case '*':
			for i := 0; i <= len(s); i++ {
				if matchGlobRecursive(pattern[1:], s[i:]) {
					return true
				}
			}
			return false
		case '?':
			if len(s) == 0 {
				return false
			}
			s = s[1:]
			pattern = pattern[1:]
		default:
			if len(s) == 0 || s[0] != pattern[0] {
				return false
			}
			s = s[1:]
			pattern = pattern[1:]
		}
	}
	return len(s) == 0
}
