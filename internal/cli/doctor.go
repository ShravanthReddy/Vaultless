// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Shravanth. All rights reserved.

package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/vaultless/vaultless/internal/output"
	"github.com/vaultless/vaultless/internal/service"
)

func newDoctorCmd(gf *GlobalFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "doctor",
		Short: "Run health checks on the Vaultless project",
		Example: `  vaultless doctor`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ac, err := initAppContext(gf)
			if err != nil {
				return err
			}
			defer ac.close()

			svc := service.NewDoctorService(ac.database, ac.cfg.ProjectPath, ac.cfg.ProjectID, ac.projectKey)
			checks := svc.RunAll(newContext())

			if ac.cfg.OutputJSON {
				return ac.formatter.PrintJSON(checks)
			}

			hasFailure := false
			tbl := output.NewTable(os.Stdout, ac.formatter.NoColor, "CHECK", "STATUS", "MESSAGE")
			for _, c := range checks {
				status := c.Status
				if c.Status == "fail" {
					hasFailure = true
				}
				tbl.AddRow(c.Name, status, c.Message)
			}
			tbl.Flush()

			fmt.Println()
			if hasFailure {
				ac.formatter.Error("Some checks failed. Review the issues above.")
				os.Exit(1)
			}
			ac.formatter.Success("All checks passed!")
			return nil
		},
	}
}
