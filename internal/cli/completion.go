// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Shravanth. All rights reserved.

package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

func newCompletionCmd(gf *GlobalFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "completion [bash|zsh|fish|powershell]",
		Short: "Generate shell completion scripts",
		Long: `Generate shell completion scripts for Vaultless.

To load completions:

Bash:
  $ source <(vaultless completion bash)
  # To load completions for each session, execute once:
  $ vaultless completion bash > /etc/bash_completion.d/vaultless

Zsh:
  $ source <(vaultless completion zsh)
  # To load completions for each session, execute once:
  $ vaultless completion zsh > "${fpath[1]}/_vaultless"

Fish:
  $ vaultless completion fish | source
  # To load completions for each session, execute once:
  $ vaultless completion fish > ~/.config/fish/completions/vaultless.fish

PowerShell:
  PS> vaultless completion powershell | Out-String | Invoke-Expression`,
		Args:      cobra.ExactArgs(1),
		ValidArgs: []string{"bash", "zsh", "fish", "powershell"},
		RunE: func(cmd *cobra.Command, args []string) error {
			switch args[0] {
			case "bash":
				return cmd.Root().GenBashCompletionV2(os.Stdout, true)
			case "zsh":
				return cmd.Root().GenZshCompletion(os.Stdout)
			case "fish":
				return cmd.Root().GenFishCompletion(os.Stdout, true)
			case "powershell":
				return cmd.Root().GenPowerShellCompletionWithDesc(os.Stdout)
			default:
				return fmt.Errorf("unsupported shell: %s", args[0])
			}
		},
	}
	return cmd
}
