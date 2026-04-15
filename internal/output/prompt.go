// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Shravanth. All rights reserved.

package output

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"golang.org/x/term"
)

// PromptConfirm asks the user for y/n confirmation.
// Returns true if the user confirms, false otherwise.
// Returns an error if stdin is not a TTY (CI/CD environment).
func PromptConfirm(message string) (bool, error) {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return false, fmt.Errorf("confirmation required but stdin is not a terminal. Use --force to skip")
	}

	fmt.Fprintf(os.Stderr, "%s [y/N]: ", message)
	reader := bufio.NewReader(os.Stdin)
	input, err := reader.ReadString('\n')
	if err != nil {
		return false, err
	}

	input = strings.TrimSpace(strings.ToLower(input))
	return input == "y" || input == "yes", nil
}

// PromptPassword reads a password from the terminal without echoing.
func PromptPassword(message string) (string, error) {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		// Read from stdin pipe (e.g., echo "password" | vaultless init)
		reader := bufio.NewReader(os.Stdin)
		line, err := reader.ReadString('\n')
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(line), nil
	}

	fmt.Fprintf(os.Stderr, "%s: ", message)
	password, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr) // newline after password input
	if err != nil {
		return "", err
	}
	return string(password), nil
}

// PromptString reads a string input from the user.
func PromptString(message, defaultVal string) (string, error) {
	if defaultVal != "" {
		fmt.Fprintf(os.Stderr, "%s [%s]: ", message, defaultVal)
	} else {
		fmt.Fprintf(os.Stderr, "%s: ", message)
	}

	reader := bufio.NewReader(os.Stdin)
	input, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}

	input = strings.TrimSpace(input)
	if input == "" {
		return defaultVal, nil
	}
	return input, nil
}
