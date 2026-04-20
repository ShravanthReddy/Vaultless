// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Shravanth. All rights reserved.

package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newVersionCmd(version, commit, date string) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the version of Vaultless",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("vaultless %s (commit: %s, built: %s)\n", version, commit, date)
		},
	}
}
