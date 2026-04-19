// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Shravanth. All rights reserved.

package service

import (
	"strings"
	"testing"
)

func TestParseEnvFile_Simple(t *testing.T) {
	input := `
KEY1=value1
KEY2=value2
`
	entries, err := ParseEnvFile(strings.NewReader(input))
	if err != nil {
		t.Fatalf("ParseEnvFile failed: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}
	if entries[0].Key != "KEY1" || entries[0].Value != "value1" {
		t.Errorf("entry 0: got %q=%q", entries[0].Key, entries[0].Value)
	}
}

func TestParseEnvFile_Quoted(t *testing.T) {
	input := `
SINGLE='raw value'
DOUBLE="with\nnewline"
`
	entries, err := ParseEnvFile(strings.NewReader(input))
	if err != nil {
		t.Fatalf("ParseEnvFile failed: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}
	if entries[0].Value != "raw value" {
		t.Errorf("single quote: got %q", entries[0].Value)
	}
	if entries[1].Value != "with\nnewline" {
		t.Errorf("double quote: got %q", entries[1].Value)
	}
}

func TestParseEnvFile_Comments(t *testing.T) {
	input := `
# This is a comment
KEY=value
# Another comment
`
	entries, err := ParseEnvFile(strings.NewReader(input))
	if err != nil {
		t.Fatalf("ParseEnvFile failed: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
}

func TestParseEnvFile_Export(t *testing.T) {
	input := `export KEY=value`
	entries, err := ParseEnvFile(strings.NewReader(input))
	if err != nil {
		t.Fatalf("ParseEnvFile failed: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].Key != "KEY" {
		t.Errorf("expected KEY, got %q", entries[0].Key)
	}
}

func TestParseEnvFile_InlineComment(t *testing.T) {
	input := `KEY=value # this is a comment`
	entries, err := ParseEnvFile(strings.NewReader(input))
	if err != nil {
		t.Fatalf("ParseEnvFile failed: %v", err)
	}
	if entries[0].Value != "value" {
		t.Errorf("expected 'value', got %q", entries[0].Value)
	}
}

func TestParseJSONFile_Flat(t *testing.T) {
	input := `{"KEY1": "val1", "KEY2": "val2"}`
	entries, err := ParseJSONFile(strings.NewReader(input))
	if err != nil {
		t.Fatalf("ParseJSONFile failed: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}
}

func TestParseJSONFile_Nested(t *testing.T) {
	input := `{"database": {"host": "localhost", "port": 5432}}`
	entries, err := ParseJSONFile(strings.NewReader(input))
	if err != nil {
		t.Fatalf("ParseJSONFile failed: %v", err)
	}
	found := false
	for _, e := range entries {
		if e.Key == "DATABASE_HOST" && e.Value == "localhost" {
			found = true
		}
	}
	if !found {
		t.Error("expected DATABASE_HOST=localhost in flattened output")
	}
}
