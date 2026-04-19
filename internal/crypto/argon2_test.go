// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Shravanth. All rights reserved.

package crypto

import (
	"bytes"
	"testing"
)

func TestDeriveKey_Deterministic(t *testing.T) {
	password := []byte("test-password")
	salt := []byte("1234567890123456") // 16 bytes

	key1, _, err := DeriveKey(password, salt, &TestArgon2Params)
	if err != nil {
		t.Fatalf("DeriveKey failed: %v", err)
	}

	key2, _, err := DeriveKey(password, salt, &TestArgon2Params)
	if err != nil {
		t.Fatalf("DeriveKey failed: %v", err)
	}

	if !bytes.Equal(key1, key2) {
		t.Fatal("same password+salt should produce same key")
	}
}

func TestDeriveKey_DifferentSalts(t *testing.T) {
	password := []byte("test-password")
	salt1 := []byte("1234567890123456")
	salt2 := []byte("6543210987654321")

	key1, _, _ := DeriveKey(password, salt1, &TestArgon2Params)
	key2, _, _ := DeriveKey(password, salt2, &TestArgon2Params)

	if bytes.Equal(key1, key2) {
		t.Fatal("different salts should produce different keys")
	}
}

func TestDeriveKey_GeneratesSalt(t *testing.T) {
	password := []byte("test-password")

	_, salt, err := DeriveKey(password, nil, &TestArgon2Params)
	if err != nil {
		t.Fatalf("DeriveKey failed: %v", err)
	}

	if len(salt) != int(TestArgon2Params.SaltLength) {
		t.Fatalf("expected salt length %d, got %d", TestArgon2Params.SaltLength, len(salt))
	}
}

func TestDeriveKey_KeyLength(t *testing.T) {
	key, _, err := DeriveKey([]byte("password"), nil, &TestArgon2Params)
	if err != nil {
		t.Fatalf("DeriveKey failed: %v", err)
	}

	if len(key) != int(TestArgon2Params.KeyLength) {
		t.Fatalf("expected key length %d, got %d", TestArgon2Params.KeyLength, len(key))
	}
}
