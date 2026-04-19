// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Shravanth. All rights reserved.

package crypto

import (
	"os"
	"testing"
)

func TestVerificationToken_Roundtrip(t *testing.T) {
	masterKey := make([]byte, KeySize)
	for i := range masterKey {
		masterKey[i] = byte(i)
	}

	token, err := CreateVerificationToken(masterKey)
	if err != nil {
		t.Fatalf("CreateVerificationToken failed: %v", err)
	}

	if !VerifyMasterKey(masterKey, token) {
		t.Fatal("verification should succeed with correct key")
	}

	wrongKey := make([]byte, KeySize)
	wrongKey[0] = 255
	if VerifyMasterKey(wrongKey, token) {
		t.Fatal("verification should fail with wrong key")
	}
}

func TestProjectKey_StoreLoad(t *testing.T) {
	tmpDir := t.TempDir()
	os.Setenv("VAULTLESS_HOME", tmpDir)
	defer os.Unsetenv("VAULTLESS_HOME")

	masterKey := make([]byte, KeySize)
	for i := range masterKey {
		masterKey[i] = byte(i)
	}

	projectKey, err := GenerateProjectKey()
	if err != nil {
		t.Fatalf("GenerateProjectKey failed: %v", err)
	}

	projectID := "test-project-id"
	if err := StoreProjectKey(projectID, projectKey, masterKey); err != nil {
		t.Fatalf("StoreProjectKey failed: %v", err)
	}

	loaded, err := LoadProjectKey(projectID, masterKey)
	if err != nil {
		t.Fatalf("LoadProjectKey failed: %v", err)
	}

	if len(loaded) != KeySize {
		t.Fatalf("expected key size %d, got %d", KeySize, len(loaded))
	}

	for i := range projectKey {
		if loaded[i] != projectKey[i] {
			t.Fatalf("key mismatch at byte %d", i)
		}
	}
}
