// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Shravanth. All rights reserved.

package service

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"gopkg.in/yaml.v3"
)

// EnvEntry represents a parsed key-value pair from an import file.
type EnvEntry struct {
	Key   string
	Value string
	Line  int
}

// ImportResult contains the results of an import operation.
type ImportResult struct {
	Imported   int
	Skipped    int
	Overwritten int
}

// ParseEnvFile parses a .env file into key-value entries.
func ParseEnvFile(reader io.Reader) ([]EnvEntry, error) {
	var entries []EnvEntry
	scanner := bufio.NewScanner(reader)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		line = strings.TrimPrefix(line, "export ")

		idx := strings.IndexByte(line, '=')
		if idx == -1 {
			continue
		}

		key := strings.TrimSpace(line[:idx])
		value := line[idx+1:]
		value = parseEnvValue(value)

		entries = append(entries, EnvEntry{Key: key, Value: value, Line: lineNum})
	}

	return entries, scanner.Err()
}

func parseEnvValue(raw string) string {
	raw = strings.TrimSpace(raw)

	if len(raw) >= 2 {
		if raw[0] == '\'' && raw[len(raw)-1] == '\'' {
			return raw[1 : len(raw)-1]
		}
		if raw[0] == '"' && raw[len(raw)-1] == '"' {
			return processEscapes(raw[1 : len(raw)-1])
		}
	}

	if idx := strings.Index(raw, " #"); idx != -1 {
		raw = strings.TrimSpace(raw[:idx])
	}

	return raw
}

func processEscapes(s string) string {
	s = strings.ReplaceAll(s, `\n`, "\n")
	s = strings.ReplaceAll(s, `\t`, "\t")
	s = strings.ReplaceAll(s, `\\`, "\\")
	s = strings.ReplaceAll(s, `\"`, "\"")
	return s
}

// ParseJSONFile parses a JSON file (flat or nested) into entries.
func ParseJSONFile(reader io.Reader) ([]EnvEntry, error) {
	var data map[string]any
	if err := json.NewDecoder(reader).Decode(&data); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}
	return flattenMap(data, ""), nil
}

// ParseYAMLFile parses a YAML file (flat or nested) into entries.
func ParseYAMLFile(reader io.Reader) ([]EnvEntry, error) {
	var data map[string]any
	if err := yaml.NewDecoder(reader).Decode(&data); err != nil {
		return nil, fmt.Errorf("invalid YAML: %w", err)
	}
	return flattenMap(data, ""), nil
}

func flattenMap(m map[string]any, prefix string) []EnvEntry {
	var entries []EnvEntry
	for k, v := range m {
		key := k
		if prefix != "" {
			key = prefix + "_" + k
		}
		switch val := v.(type) {
		case map[string]any:
			entries = append(entries, flattenMap(val, key)...)
		default:
			entries = append(entries, EnvEntry{
				Key:   strings.ToUpper(strings.ReplaceAll(key, ".", "_")),
				Value: fmt.Sprintf("%v", val),
			})
		}
	}
	return entries
}
