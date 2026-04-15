// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Shravanth. All rights reserved.

package output

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
)

// Table provides TTY-aware table formatting.
type Table struct {
	writer  *tabwriter.Writer
	headers []string
	noColor bool
}

// NewTable creates a new table writer.
func NewTable(w io.Writer, noColor bool, headers ...string) *Table {
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	t := &Table{
		writer:  tw,
		headers: headers,
		noColor: noColor,
	}
	if len(headers) > 0 {
		if !noColor {
			fmt.Fprintf(tw, "\033[1m%s\033[0m\n", strings.Join(headers, "\t"))
		} else {
			fmt.Fprintln(tw, strings.Join(headers, "\t"))
		}
	}
	return t
}

// AddRow adds a row to the table.
func (t *Table) AddRow(values ...string) {
	fmt.Fprintln(t.writer, strings.Join(values, "\t"))
}

// Flush writes the table output.
func (t *Table) Flush() error {
	return t.writer.Flush()
}
