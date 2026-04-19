// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Shravanth. All rights reserved.

package crypto

import (
	"strings"
	"testing"
)

func TestGenerateUUID(t *testing.T) {
	uuid := GenerateUUID()
	if uuid == "" {
		t.Fatal("expected non-empty UUID")
	}

	// UUID v4 format: 8-4-4-4-12 hex chars
	parts := strings.Split(uuid, "-")
	if len(parts) != 5 {
		t.Fatalf("expected 5 parts, got %d in %q", len(parts), uuid)
	}
}

func TestGenerateUUID_Unique(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		uuid := GenerateUUID()
		if seen[uuid] {
			t.Fatalf("duplicate UUID: %s", uuid)
		}
		seen[uuid] = true
	}
}

func TestGenerateRandomBytes(t *testing.T) {
	tests := []int{1, 16, 32, 64}
	for _, n := range tests {
		b, err := GenerateRandomBytes(n)
		if err != nil {
			t.Fatalf("GenerateRandomBytes(%d): %v", n, err)
		}
		if len(b) != n {
			t.Fatalf("expected %d bytes, got %d", n, len(b))
		}
	}
}

func TestGenerateRandomBytes_NotAllZeros(t *testing.T) {
	b, _ := GenerateRandomBytes(32)
	allZero := true
	for _, v := range b {
		if v != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Fatal("32 random bytes should not all be zero")
	}
}

func TestGenerateTokenKey(t *testing.T) {
	key := GenerateTokenKey()
	if !strings.HasPrefix(key, "vlt_") {
		t.Fatalf("expected 'vlt_' prefix, got %q", key)
	}
	// vlt_ + 64 hex chars (32 bytes)
	if len(key) != 4+64 {
		t.Fatalf("expected length 68, got %d", len(key))
	}
}

func TestGenerateTokenKey_Unique(t *testing.T) {
	k1 := GenerateTokenKey()
	k2 := GenerateTokenKey()
	if k1 == k2 {
		t.Fatal("two token keys should differ")
	}
}
