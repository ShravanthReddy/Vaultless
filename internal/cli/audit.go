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

func newAuditCmd(gf *GlobalFlags) *cobra.Command {
	var key, user, env, from, to string
	var verify bool
	var limit int

	cmd := &cobra.Command{
		Use:   "audit",
		Short: "View audit log",
		Long:  `Display recent audit log entries with optional filters.`,
		Example: `  vaultless audit
  vaultless audit --key API_KEY
  vaultless audit --user alice --env prod
  vaultless audit --from 2026-01-01 --to 2026-04-01
  vaultless audit --verify`,
		Aliases: []string{"log"},
		RunE: func(cmd *cobra.Command, args []string) error {
			ac, err := initAppContext(gf)
			if err != nil {
				return err
			}
			defer ac.close()

			if verify {
				valid, invalid, err := ac.audit.Verify()
				if err != nil {
					return err
				}
				if invalid > 0 {
					ac.formatter.Error("Audit log integrity check failed: %d valid, %d invalid entries", valid, invalid)
					os.Exit(1)
				}
				ac.formatter.Success("Audit log integrity verified: %d entries, all valid", valid)
				return nil
			}

			q := &service.AuditQuery{
				Key:         key,
				User:        user,
				Environment: env,
				Limit:       limit,
			}

			if from != "" {
				t, err := time.Parse("2006-01-02", from)
				if err != nil {
					return fmt.Errorf("invalid --from date: %w", err)
				}
				q.From = &t
			}
			if to != "" {
				t, err := time.Parse("2006-01-02", to)
				if err != nil {
					return fmt.Errorf("invalid --to date: %w", err)
				}
				q.To = &t
			}

			entries, err := ac.audit.Query(q)
			if err != nil {
				return err
			}

			if ac.cfg.OutputJSON {
				return ac.formatter.PrintJSON(entries)
			}

			if len(entries) == 0 {
				ac.formatter.Println("No audit entries found.")
				return nil
			}

			tbl := output.NewTable(os.Stdout, ac.formatter.NoColor, "TIME", "OP", "USER", "ENV", "KEY", "STATUS")
			for _, e := range entries {
				status := "ok"
				if !e.Success {
					status = "fail"
				}
				tbl.AddRow(
					e.Timestamp.Format("2006-01-02 15:04:05"),
					e.Operation,
					e.User,
					e.Environment,
					e.Key,
					status,
				)
			}
			return tbl.Flush()
		},
	}

	cmd.Flags().StringVar(&key, "key", "", "Filter by secret key")
	cmd.Flags().StringVar(&user, "user", "", "Filter by user")
	cmd.Flags().StringVar(&env, "env-filter", "", "Filter by environment")
	cmd.Flags().StringVar(&from, "from", "", "Filter from date (YYYY-MM-DD)")
	cmd.Flags().StringVar(&to, "to", "", "Filter to date (YYYY-MM-DD)")
	cmd.Flags().BoolVar(&verify, "verify", false, "Verify audit log integrity")
	cmd.Flags().IntVar(&limit, "limit", 50, "Maximum entries to display")

	return cmd
}
