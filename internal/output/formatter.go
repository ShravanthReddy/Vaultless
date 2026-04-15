// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Shravanth. All rights reserved.

package output

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"golang.org/x/term"
)

// Formatter handles output formatting based on context (TTY vs pipe, JSON vs text).
type Formatter struct {
	Writer  io.Writer
	JSON    bool
	Quiet   bool
	NoColor bool
	IsTTY   bool
}

// New creates a new Formatter with TTY detection.
func New(jsonMode, quiet, noColor bool) *Formatter {
	isTTY := term.IsTerminal(int(os.Stdout.Fd()))
	if os.Getenv("NO_COLOR") != "" || os.Getenv("VAULTLESS_NO_COLOR") != "" {
		noColor = true
	}
	return &Formatter{
		Writer:  os.Stdout,
		JSON:    jsonMode,
		Quiet:   quiet,
		NoColor: noColor || !isTTY,
		IsTTY:   isTTY,
	}
}

// PrintJSON writes v as formatted JSON to the writer.
func (f *Formatter) PrintJSON(v any) error {
	enc := json.NewEncoder(f.Writer)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// Println writes a line to the writer. Suppressed in quiet mode.
func (f *Formatter) Println(a ...any) {
	if f.Quiet {
		return
	}
	fmt.Fprintln(f.Writer, a...)
}

// Printf writes formatted output. Suppressed in quiet mode.
func (f *Formatter) Printf(format string, a ...any) {
	if f.Quiet {
		return
	}
	fmt.Fprintf(f.Writer, format, a...)
}

// PrintResult writes output that should always be shown (e.g., secret values).
func (f *Formatter) PrintResult(s string) {
	fmt.Fprint(f.Writer, s)
}

// Success prints a success message with optional green coloring.
func (f *Formatter) Success(format string, a ...any) {
	msg := fmt.Sprintf(format, a...)
	if f.Quiet {
		return
	}
	if !f.NoColor {
		fmt.Fprintf(f.Writer, "\033[32m%s\033[0m\n", msg)
	} else {
		fmt.Fprintln(f.Writer, msg)
	}
}

// Error prints an error message to stderr.
func (f *Formatter) Error(format string, a ...any) {
	msg := fmt.Sprintf(format, a...)
	if !f.NoColor {
		fmt.Fprintf(os.Stderr, "\033[31mError: %s\033[0m\n", msg)
	} else {
		fmt.Fprintf(os.Stderr, "Error: %s\n", msg)
	}
}

// Warn prints a warning message.
func (f *Formatter) Warn(format string, a ...any) {
	if f.Quiet {
		return
	}
	msg := fmt.Sprintf(format, a...)
	if !f.NoColor {
		fmt.Fprintf(os.Stderr, "\033[33mWarning: %s\033[0m\n", msg)
	} else {
		fmt.Fprintf(os.Stderr, "Warning: %s\n", msg)
	}
}
