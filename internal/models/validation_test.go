// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Shravanth. All rights reserved.

package models

import "testing"

func TestValidateKeyName_Valid(t *testing.T) {
	valid := []string{"A", "API_KEY", "DATABASE_URL", "X123", "A_B_C"}
	for _, k := range valid {
		if err := ValidateKeyName(k); err != nil {
			t.Errorf("expected valid key %q, got error: %v", k, err)
		}
	}
}

func TestValidateKeyName_Invalid(t *testing.T) {
	invalid := []string{"", "lowercase", "123ABC", "has-dash", "has space", "a"}
	for _, k := range invalid {
		if err := ValidateKeyName(k); err == nil {
			t.Errorf("expected invalid key %q to fail validation", k)
		}
	}
}

func TestValidateEnvName_Valid(t *testing.T) {
	valid := []string{"dev", "staging", "prod", "my-env", "test1"}
	for _, n := range valid {
		if err := ValidateEnvName(n); err != nil {
			t.Errorf("expected valid env %q, got error: %v", n, err)
		}
	}
}

func TestValidateEnvName_Invalid(t *testing.T) {
	invalid := []string{"", "UPPER", "1starts-with-num", "has_underscore", "has space"}
	for _, n := range invalid {
		if err := ValidateEnvName(n); err == nil {
			t.Errorf("expected invalid env %q to fail validation", n)
		}
	}
}

func TestValidatePassword(t *testing.T) {
	if err := ValidatePassword("12345678"); err != nil {
		t.Error("8-char password should be valid")
	}
	if err := ValidatePassword("short"); err == nil {
		t.Error("5-char password should be invalid")
	}
}

func TestValidateSecretValue(t *testing.T) {
	if err := ValidateSecretValue([]byte("normal value")); err != nil {
		t.Error("normal value should be valid")
	}

	big := make([]byte, MaxValueSize+1)
	if err := ValidateSecretValue(big); err == nil {
		t.Error("value exceeding max size should be invalid")
	}
}
