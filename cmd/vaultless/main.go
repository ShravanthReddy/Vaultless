// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Shravanth. All rights reserved.

package main

import (
	"fmt"
	"os"

	"github.com/vaultless/vaultless/internal/cli"
)

// Set by -ldflags at build time.
var (
	version = "dev"
	commit  = "unknown"
	date    = "unknown"
)

func main() {
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(os.Stderr, "Error: unexpected internal error. Please report this at https://github.com/vaultless/vaultless/issues\n")
			os.Exit(1)
		}
	}()

	root := cli.NewRootCommand(version, commit, date)
	if err := root.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		os.Exit(1)
	}
}
