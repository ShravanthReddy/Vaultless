// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Shravanth. All rights reserved.

package service

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestExport_EnvFormat(t *testing.T) {
	secrets := map[string][]byte{
		"DB_HOST": []byte("localhost"),
		"DB_PORT": []byte("5432"),
	}

	var buf bytes.Buffer
	err := Export(&buf, secrets, "development", &ExportOptions{Format: FormatEnv})
	if err != nil {
		t.Fatalf("Export: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "DB_HOST=localhost") {
		t.Fatalf("expected DB_HOST=localhost in output:\n%s", output)
	}
	if !strings.Contains(output, "DB_PORT=5432") {
		t.Fatalf("expected DB_PORT=5432 in output:\n%s", output)
	}
	if !strings.Contains(output, "# Environment: development") {
		t.Fatalf("expected environment header in output:\n%s", output)
	}
}

func TestExport_EnvFormat_QuotedValues(t *testing.T) {
	secrets := map[string][]byte{
		"SIMPLE": []byte("simple"),
		"SPACED": []byte("has spaces"),
	}

	var buf bytes.Buffer
	_ = Export(&buf, secrets, "dev", &ExportOptions{Format: FormatEnv})

	output := buf.String()
	if !strings.Contains(output, "SIMPLE=simple") {
		t.Fatalf("simple value should not be quoted:\n%s", output)
	}
	if !strings.Contains(output, `SPACED="has spaces"`) {
		t.Fatalf("spaced value should be quoted:\n%s", output)
	}
}

func TestExport_JSONFormat(t *testing.T) {
	secrets := map[string][]byte{
		"KEY1": []byte("val1"),
		"KEY2": []byte("val2"),
	}

	var buf bytes.Buffer
	err := Export(&buf, secrets, "dev", &ExportOptions{Format: FormatJSON})
	if err != nil {
		t.Fatalf("Export JSON: %v", err)
	}

	var result map[string]string
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("invalid JSON output: %v", err)
	}
	if result["KEY1"] != "val1" || result["KEY2"] != "val2" {
		t.Fatalf("unexpected JSON: %v", result)
	}
}

func TestExport_YAMLFormat(t *testing.T) {
	secrets := map[string][]byte{
		"APP_NAME": []byte("myapp"),
	}

	var buf bytes.Buffer
	err := Export(&buf, secrets, "dev", &ExportOptions{Format: FormatYAML})
	if err != nil {
		t.Fatalf("Export YAML: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "APP_NAME: myapp") {
		t.Fatalf("expected YAML output, got:\n%s", output)
	}
}

func TestExport_Filter(t *testing.T) {
	secrets := map[string][]byte{
		"DB_HOST":  []byte("localhost"),
		"DB_PORT":  []byte("5432"),
		"APP_NAME": []byte("myapp"),
	}

	var buf bytes.Buffer
	err := Export(&buf, secrets, "dev", &ExportOptions{Format: FormatJSON, Filter: "DB_*"})
	if err != nil {
		t.Fatalf("Export: %v", err)
	}

	var result map[string]string
	json.Unmarshal(buf.Bytes(), &result)
	if len(result) != 2 {
		t.Fatalf("expected 2 filtered secrets, got %d", len(result))
	}
	if _, ok := result["APP_NAME"]; ok {
		t.Fatal("APP_NAME should have been filtered out")
	}
}

func TestExport_Exclude(t *testing.T) {
	secrets := map[string][]byte{
		"DB_HOST":  []byte("localhost"),
		"DB_PORT":  []byte("5432"),
		"APP_NAME": []byte("myapp"),
	}

	var buf bytes.Buffer
	_ = Export(&buf, secrets, "dev", &ExportOptions{Format: FormatJSON, Exclude: "DB_*"})

	var result map[string]string
	json.Unmarshal(buf.Bytes(), &result)
	if len(result) != 1 {
		t.Fatalf("expected 1 secret after exclude, got %d", len(result))
	}
	if result["APP_NAME"] != "myapp" {
		t.Fatalf("expected APP_NAME=myapp, got %v", result)
	}
}

func TestExport_Empty(t *testing.T) {
	var buf bytes.Buffer
	err := Export(&buf, map[string][]byte{}, "dev", &ExportOptions{Format: FormatJSON})
	if err != nil {
		t.Fatalf("Export empty: %v", err)
	}

	var result map[string]string
	json.Unmarshal(buf.Bytes(), &result)
	if len(result) != 0 {
		t.Fatalf("expected empty map, got %v", result)
	}
}
