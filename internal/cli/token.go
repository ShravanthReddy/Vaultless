// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Shravanth. All rights reserved.

package cli

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
	"github.com/vaultless/vaultless/internal/output"
	"github.com/vaultless/vaultless/internal/service"
)

func newTokenCmd(gf *GlobalFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "token",
		Short: "Manage access tokens",
	}

	cmd.AddCommand(
		newTokenCreateCmd(gf),
		newTokenListCmd(gf),
		newTokenRevokeCmd(gf),
	)
	return cmd
}

func newTokenCreateCmd(gf *GlobalFlags) *cobra.Command {
	var name, permission, expiry string

	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a new access token",
		Example: `  vaultless token create --name ci-deploy --permission read-only --expiry 90d
  vaultless token create --name admin --permission read-write`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ac, err := initAppContext(gf)
			if err != nil {
				return err
			}
			defer ac.close()

			if name == "" {
				return fmt.Errorf("--name is required")
			}

			var expiryDuration time.Duration
			if expiry != "" {
				expiryDuration, err = parseDuration(expiry)
				if err != nil {
					return fmt.Errorf("invalid expiry: %w", err)
				}
			}

			svc := service.NewTokensService(ac.database, ac.identity)
			result, err := svc.Create(newContext(), name, permission, expiryDuration)
			if err != nil {
				return err
			}

			if ac.cfg.OutputJSON {
				return ac.formatter.PrintJSON(result)
			}

			ac.formatter.Success("Token created: %s", name)
			fmt.Println()
			fmt.Printf("Token key (shown ONCE — save it now):\n  %s\n\n", result.Key)
			fmt.Printf("Permission: %s\n", result.Permission)
			if result.ExpiresAt != nil {
				fmt.Printf("Expires: %s\n", result.ExpiresAt.Format(time.RFC3339))
			}
			fmt.Println()
			fmt.Println("Use in CI/CD:")
			fmt.Printf("  export VAULTLESS_TOKEN=%s\n", result.Key)

			return nil
		},
	}

	cmd.Flags().StringVar(&name, "name", "", "Token name (required)")
	cmd.Flags().StringVar(&permission, "permission", "read-only", "Permission level: read-only, read-write")
	cmd.Flags().StringVar(&expiry, "expiry", "", "Token expiry (e.g., 90d, 24h)")

	return cmd
}

func newTokenListCmd(gf *GlobalFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List all tokens",
		RunE: func(cmd *cobra.Command, args []string) error {
			ac, err := initAppContext(gf)
			if err != nil {
				return err
			}
			defer ac.close()

			svc := service.NewTokensService(ac.database, ac.identity)
			tokens, err := svc.List(newContext())
			if err != nil {
				return err
			}

			if ac.cfg.OutputJSON {
				return ac.formatter.PrintJSON(tokens)
			}

			if len(tokens) == 0 {
				ac.formatter.Println("No tokens found.")
				return nil
			}

			tbl := output.NewTable(os.Stdout, ac.formatter.NoColor, "NAME", "PERMISSION", "CREATED", "EXPIRES", "STATUS")
			for _, t := range tokens {
				expires := "never"
				if t.ExpiresAt != nil {
					expires = t.ExpiresAt.Format("2006-01-02")
				}
				status := "active"
				if t.IsRevoked {
					status = "revoked"
				} else if t.ExpiresAt != nil && t.ExpiresAt.Before(time.Now()) {
					status = "expired"
				}
				tbl.AddRow(t.Name, t.Permission, t.CreatedAt.Format("2006-01-02"), expires, status)
			}
			return tbl.Flush()
		},
	}
}

func newTokenRevokeCmd(gf *GlobalFlags) *cobra.Command {
	return &cobra.Command{
		Use:     "revoke NAME",
		Short:   "Revoke a token",
		Example: `  vaultless token revoke ci-deploy`,
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ac, err := initAppContext(gf)
			if err != nil {
				return err
			}
			defer ac.close()

			svc := service.NewTokensService(ac.database, ac.identity)
			if err := svc.Revoke(newContext(), args[0]); err != nil {
				return err
			}

			ac.formatter.Success("Token '%s' revoked", args[0])
			return nil
		},
	}
}

func parseDuration(s string) (time.Duration, error) {
	// Support "90d" style
	if len(s) > 1 && s[len(s)-1] == 'd' {
		var days int
		if _, err := fmt.Sscanf(s, "%dd", &days); err == nil {
			return time.Duration(days) * 24 * time.Hour, nil
		}
	}
	return time.ParseDuration(s)
}
