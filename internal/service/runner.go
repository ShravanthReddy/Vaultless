// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Shravanth. All rights reserved.

package service

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

// RunOptions configures how secrets are injected into a command.
type RunOptions struct {
	Command    string
	Args       []string
	Env        string
	Only       string
	Exclude    string
	NoOverride bool
	DotEnv     bool
	Watch      bool
}

// Runner executes commands with injected secrets.
type Runner struct {
	secrets *SecretsService
}

func NewRunner(secrets *SecretsService) *Runner {
	return &Runner{secrets: secrets}
}

// Exec runs a command with secrets injected as environment variables.
func (r *Runner) Exec(ctx context.Context, opts *RunOptions) (int, error) {
	secrets, err := r.secrets.ListDecrypted(ctx, opts.Env)
	if err != nil {
		return 0, fmt.Errorf("failed to load secrets: %w", err)
	}

	// Apply filters
	filtered := applyGlobFilters(secrets, opts.Only, opts.Exclude)

	if opts.DotEnv {
		return r.execWithDotEnv(ctx, opts, filtered)
	}

	// Build environment
	env := os.Environ()
	for key, value := range filtered {
		if opts.NoOverride {
			if _, exists := os.LookupEnv(key); exists {
				continue
			}
		}
		env = append(env, fmt.Sprintf("%s=%s", key, string(value)))
	}

	// Zero secrets from memory
	for _, v := range filtered {
		ZeroSecretBytes(v)
	}

	cmd := exec.CommandContext(ctx, opts.Command, opts.Args...)
	cmd.Env = env
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			if status, ok := exitErr.Sys().(syscall.WaitStatus); ok {
				return status.ExitStatus(), nil
			}
			return 1, nil
		}
		// Command not found
		if _, lookErr := exec.LookPath(opts.Command); lookErr != nil {
			return 127, nil
		}
		return 1, nil
	}
	return 0, nil
}

func (r *Runner) execWithDotEnv(ctx context.Context, opts *RunOptions, secrets map[string][]byte) (int, error) {
	tmpDir, err := os.MkdirTemp("", "vaultless-*")
	if err != nil {
		return 0, fmt.Errorf("failed to create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	dotenvPath := filepath.Join(tmpDir, ".env")
	var lines []string
	for key, value := range secrets {
		lines = append(lines, fmt.Sprintf("%s=%s", key, quoteEnvValue(string(value))))
	}
	if err := os.WriteFile(dotenvPath, []byte(strings.Join(lines, "\n")+"\n"), 0600); err != nil {
		return 0, fmt.Errorf("failed to write .env: %w", err)
	}

	// Zero secrets
	for _, v := range secrets {
		ZeroSecretBytes(v)
	}

	env := append(os.Environ(), "DOTENV_PATH="+dotenvPath)
	cmd := exec.CommandContext(ctx, opts.Command, opts.Args...)
	cmd.Env = env
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			if status, ok := exitErr.Sys().(syscall.WaitStatus); ok {
				return status.ExitStatus(), nil
			}
			return 1, nil
		}
		return 1, nil
	}
	return 0, nil
}

// ZeroSecretBytes zeroes out a byte slice for secure memory cleanup.
func ZeroSecretBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// applyGlobFilters filters secrets by include/exclude glob patterns.
func applyGlobFilters(secrets map[string][]byte, only, exclude string) map[string][]byte {
	if only == "" && exclude == "" {
		return secrets
	}

	result := make(map[string][]byte)
	for key, value := range secrets {
		if only != "" {
			matched, _ := filepath.Match(only, key)
			if !matched {
				continue
			}
		}
		if exclude != "" {
			matched, _ := filepath.Match(exclude, key)
			if matched {
				continue
			}
		}
		result[key] = value
	}
	return result
}

// quoteEnvValue quotes a value if it contains special characters.
func quoteEnvValue(s string) string {
	needsQuoting := false
	for _, c := range s {
		if c == ' ' || c == '\n' || c == '\'' || c == '#' || c == '"' || c == '\\' {
			needsQuoting = true
			break
		}
	}
	if !needsQuoting {
		return s
	}
	s = strings.ReplaceAll(s, "\n", `\n`)
	return `"` + s + `"`
}
