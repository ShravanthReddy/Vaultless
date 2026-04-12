// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Shravanth. All rights reserved.

package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/vaultless/vaultless/internal/config"
	"github.com/vaultless/vaultless/internal/output"
	"github.com/vaultless/vaultless/internal/service"
)

func newEnvCmd(gf *GlobalFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "env",
		Short: "Manage environments",
	}

	cmd.AddCommand(
		newEnvCreateCmd(gf),
		newEnvDeleteCmd(gf),
		newEnvListCmd(gf),
		newEnvUseCmd(gf),
		newEnvCurrentCmd(gf),
		newEnvDiffCmd(gf),
		newEnvCloneCmd(gf),
	)
	return cmd
}

func newEnvCreateCmd(gf *GlobalFlags) *cobra.Command {
	return &cobra.Command{
		Use:     "create NAME",
		Short:   "Create a new environment",
		Example: `  vaultless env create testing`,
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ac, err := initAppContext(gf)
			if err != nil {
				return err
			}
			defer ac.close()

			svc := service.NewEnvironmentsService(ac.database, ac.cfg.ProjectID)
			if err := svc.Create(newContext(), args[0]); err != nil {
				return err
			}

			ac.formatter.Success("Environment '%s' created", args[0])
			return nil
		},
	}
}

func newEnvDeleteCmd(gf *GlobalFlags) *cobra.Command {
	return &cobra.Command{
		Use:     "delete NAME",
		Short:   "Delete an environment and all its secrets",
		Example: `  vaultless env delete testing`,
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ac, err := initAppContext(gf)
			if err != nil {
				return err
			}
			defer ac.close()

			if !ac.cfg.Force {
				confirmed, err := output.PromptConfirm(fmt.Sprintf("Delete environment '%s' and all its secrets?", args[0]))
				if err != nil || !confirmed {
					ac.formatter.Println("Aborted.")
					return nil
				}
			}

			svc := service.NewEnvironmentsService(ac.database, ac.cfg.ProjectID)
			if err := svc.Delete(newContext(), args[0]); err != nil {
				return err
			}

			ac.formatter.Success("Environment '%s' deleted", args[0])
			return nil
		},
	}
}

func newEnvListCmd(gf *GlobalFlags) *cobra.Command {
	return &cobra.Command{
		Use:     "list",
		Short:   "List all environments",
		Example: `  vaultless env list`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ac, err := initAppContext(gf)
			if err != nil {
				return err
			}
			defer ac.close()

			svc := service.NewEnvironmentsService(ac.database, ac.cfg.ProjectID)
			envs, err := svc.List(newContext())
			if err != nil {
				return err
			}

			if ac.cfg.OutputJSON {
				return ac.formatter.PrintJSON(envs)
			}

			tbl := output.NewTable(os.Stdout, ac.formatter.NoColor, "NAME", "SECRETS", "ACTIVE")
			for _, env := range envs {
				active := ""
				if env.Name == ac.cfg.ActiveEnv {
					active = "*"
				}
				tbl.AddRow(env.Name, fmt.Sprintf("%d", env.SecretCount), active)
			}
			return tbl.Flush()
		},
	}
}

func newEnvUseCmd(gf *GlobalFlags) *cobra.Command {
	return &cobra.Command{
		Use:     "use NAME",
		Short:   "Set the active environment",
		Example: `  vaultless env use staging`,
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ac, err := initAppContext(gf)
			if err != nil {
				return err
			}
			defer ac.close()

			envName := args[0]

			// Verify environment exists
			svc := service.NewEnvironmentsService(ac.database, ac.cfg.ProjectID)
			envs, err := svc.List(newContext())
			if err != nil {
				return err
			}
			found := false
			for _, e := range envs {
				if e.Name == envName {
					found = true
					break
				}
			}
			if !found {
				return fmt.Errorf("environment '%s' not found", envName)
			}

			// Update project config
			pc, err := config.LoadProjectConfig(ac.cfg.ProjectPath)
			if err != nil {
				return err
			}
			pc.Environment.Active = envName
			if err := config.SaveProjectConfig(ac.cfg.ProjectPath, pc); err != nil {
				return err
			}

			ac.formatter.Success("Active environment set to '%s'", envName)
			return nil
		},
	}
}

func newEnvCurrentCmd(gf *GlobalFlags) *cobra.Command {
	return &cobra.Command{
		Use:     "current",
		Short:   "Show the active environment",
		Example: `  vaultless env current`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ac, err := initAppContext(gf)
			if err != nil {
				return err
			}
			defer ac.close()

			if ac.cfg.OutputJSON {
				return ac.formatter.PrintJSON(map[string]string{
					"environment": ac.cfg.ActiveEnv,
				})
			}

			ac.formatter.Printf("Active environment: %s\n", ac.cfg.ActiveEnv)
			return nil
		},
	}
}

func newEnvDiffCmd(gf *GlobalFlags) *cobra.Command {
	return &cobra.Command{
		Use:     "diff ENV1 ENV2",
		Short:   "Compare two environments",
		Example: `  vaultless env diff dev staging`,
		Args:    cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			ac, err := initAppContext(gf)
			if err != nil {
				return err
			}
			defer ac.close()

			svc := service.NewEnvironmentsService(ac.database, ac.cfg.ProjectID)
			diff, err := svc.Diff(newContext(), args[0], args[1])
			if err != nil {
				return err
			}

			if ac.cfg.OutputJSON {
				return ac.formatter.PrintJSON(diff)
			}

			if len(diff.OnlyInEnv1) > 0 {
				fmt.Printf("\nKeys only in '%s':\n", diff.Env1Name)
				for _, k := range diff.OnlyInEnv1 {
					fmt.Printf("  + %s\n", k)
				}
			}
			if len(diff.OnlyInEnv2) > 0 {
				fmt.Printf("\nKeys only in '%s':\n", diff.Env2Name)
				for _, k := range diff.OnlyInEnv2 {
					fmt.Printf("  + %s\n", k)
				}
			}
			if len(diff.InBoth) > 0 {
				fmt.Printf("\nKeys in both (values may differ):\n")
				for _, k := range diff.InBoth {
					fmt.Printf("  = %s\n", k)
				}
			}

			return nil
		},
	}
}

func newEnvCloneCmd(gf *GlobalFlags) *cobra.Command {
	return &cobra.Command{
		Use:     "clone SOURCE TARGET",
		Short:   "Clone an environment",
		Example: `  vaultless env clone dev testing`,
		Args:    cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			ac, err := initAppContext(gf)
			if err != nil {
				return err
			}
			defer ac.close()

			svc := service.NewEnvironmentsService(ac.database, ac.cfg.ProjectID)
			if err := svc.Clone(newContext(), args[0], args[1]); err != nil {
				return err
			}

			ac.formatter.Success("Environment '%s' cloned to '%s'", args[0], args[1])
			return nil
		},
	}
}
