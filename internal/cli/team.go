// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Shravanth. All rights reserved.

package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/vaultless/vaultless/internal/crypto"
	"github.com/vaultless/vaultless/internal/output"
	"github.com/vaultless/vaultless/internal/service"
)

func newTeamCmd(gf *GlobalFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "team",
		Short: "Manage team access",
	}

	cmd.AddCommand(
		newTeamInviteCmd(gf),
		newTeamJoinCmd(gf),
		newTeamListCmd(gf),
		newTeamRemoveCmd(gf),
	)
	return cmd
}

func newTeamInviteCmd(gf *GlobalFlags) *cobra.Command {
	return &cobra.Command{
		Use:     "invite EMAIL",
		Short:   "Generate an invite bundle for a team member",
		Example: `  vaultless team invite alice@example.com`,
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ac, err := initAppContext(gf)
			if err != nil {
				return err
			}
			defer ac.close()

			teamSvc := service.NewTeamService(ac.projectKey, ac.database, ac.identity)
			result, err := teamSvc.Invite(args[0])
			if err != nil {
				return err
			}

			fmt.Println("Invite bundle (share with the team member):")
			fmt.Println(result.Bundle)
			fmt.Println()
			fmt.Println("Passphrase (share via a SEPARATE channel):")
			fmt.Println(result.Passphrase)
			fmt.Println()
			fmt.Println("The team member should run:")
			fmt.Printf("  vaultless team join <bundle>\n")

			return nil
		},
	}
}

func newTeamJoinCmd(gf *GlobalFlags) *cobra.Command {
	return &cobra.Command{
		Use:     "join BUNDLE",
		Short:   "Join a project using an invite bundle",
		Example: `  vaultless team join <base64-bundle>`,
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			securityInit()
			f := output.New(gf.JSON, gf.Quiet, gf.NoColor)

			passphrase, err := output.PromptPassword("Enter passphrase")
			if err != nil {
				return err
			}

			projectKey, err := service.Join(args[0], passphrase)
			if err != nil {
				return err
			}
			defer crypto.ZeroBytes(projectKey)

			// Prompt for master password to encrypt the project key
			password, err := output.PromptPassword("Set your master password")
			if err != nil {
				return err
			}

			masterKey, _, err := crypto.DeriveKey([]byte(password), nil, nil)
			if err != nil {
				return err
			}
			defer crypto.ZeroBytes(masterKey)

			// We need a project ID — prompt or read from config
			projectID, err := output.PromptString("Project ID", "")
			if err != nil {
				return err
			}

			if err := crypto.StoreProjectKey(projectID, projectKey, masterKey); err != nil {
				return err
			}

			f.Success("Successfully joined project. Run 'vaultless pull' to get secrets.")
			return nil
		},
	}
}

func newTeamListCmd(gf *GlobalFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List team members",
		RunE: func(cmd *cobra.Command, args []string) error {
			ac, err := initAppContext(gf)
			if err != nil {
				return err
			}
			defer ac.close()

			teamSvc := service.NewTeamService(ac.projectKey, ac.database, ac.identity)
			members, err := teamSvc.List(newContext())
			if err != nil {
				return err
			}

			if ac.cfg.OutputJSON {
				return ac.formatter.PrintJSON(members)
			}

			if len(members) == 0 {
				ac.formatter.Println("No team members found. Use 'vaultless team invite' to add members.")
				return nil
			}

			tbl := output.NewTable(os.Stdout, ac.formatter.NoColor, "EMAIL", "ROLE", "INVITED BY", "JOINED", "ADDED")
			for _, m := range members {
				joined := "pending"
				if m.JoinedAt != nil {
					joined = m.JoinedAt.Format("2006-01-02")
				}
				tbl.AddRow(m.Email, m.Role, m.InvitedBy, joined, m.CreatedAt.Format("2006-01-02"))
			}
			return tbl.Flush()
		},
	}
}

func newTeamRemoveCmd(gf *GlobalFlags) *cobra.Command {
	return &cobra.Command{
		Use:     "remove EMAIL",
		Short:   "Remove a team member",
		Example: `  vaultless team remove alice@example.com`,
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ac, err := initAppContext(gf)
			if err != nil {
				return err
			}
			defer ac.close()

			teamSvc := service.NewTeamService(ac.projectKey, ac.database, ac.identity)
			if err := teamSvc.Remove(newContext(), args[0]); err != nil {
				return err
			}

			ac.formatter.Success("Team member '%s' removed", args[0])
			ac.formatter.Warn("Note: Rotate the project key to revoke their access to future secrets.")
			return nil
		},
	}
}
