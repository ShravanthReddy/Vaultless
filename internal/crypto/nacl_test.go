// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Shravanth. All rights reserved.

package crypto

import (
	"testing"
)

func TestCreateInviteBundle_DecryptRoundtrip(t *testing.T) {
	projectKey, err := GenerateProjectKey()
	if err != nil {
		t.Fatalf("GenerateProjectKey: %v", err)
	}

	passphrase := "test-passphrase-secure"
	bundle, err := CreateInviteBundle(projectKey, passphrase)
	if err != nil {
		t.Fatalf("CreateInviteBundle: %v", err)
	}

	if bundle == "" {
		t.Fatal("expected non-empty bundle")
	}

	recovered, err := DecryptInviteBundle(bundle, passphrase)
	if err != nil {
		t.Fatalf("DecryptInviteBundle: %v", err)
	}

	if len(recovered) != KeySize {
		t.Fatalf("expected key size %d, got %d", KeySize, len(recovered))
	}

	for i := range projectKey {
		if recovered[i] != projectKey[i] {
			t.Fatalf("key mismatch at byte %d", i)
		}
	}
}

func TestDecryptInviteBundle_WrongPassphrase(t *testing.T) {
	projectKey, _ := GenerateProjectKey()
	bundle, _ := CreateInviteBundle(projectKey, "correct-passphrase")

	_, err := DecryptInviteBundle(bundle, "wrong-passphrase")
	if err == nil {
		t.Fatal("expected error with wrong passphrase")
	}
}

func TestDecryptInviteBundle_InvalidBase64(t *testing.T) {
	_, err := DecryptInviteBundle("not-valid-base64!!!", "passphrase")
	if err == nil {
		t.Fatal("expected error for invalid base64")
	}
}

func TestDecryptInviteBundle_TooShort(t *testing.T) {
	// Valid base64 but too short to contain salt+nonce
	_, err := DecryptInviteBundle("AAAA", "passphrase")
	if err == nil {
		t.Fatal("expected error for too-short bundle")
	}
}

func TestCreateInviteBundle_DifferentBundlesForSameKey(t *testing.T) {
	projectKey, _ := GenerateProjectKey()

	bundle1, _ := CreateInviteBundle(projectKey, "pass1")
	bundle2, _ := CreateInviteBundle(projectKey, "pass1")

	// Bundles should differ due to random salt
	if bundle1 == bundle2 {
		t.Fatal("expected different bundles due to random salt")
	}
}

func TestGenerateKeyPair(t *testing.T) {
	pub, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	if pub == nil || priv == nil {
		t.Fatal("expected non-nil key pair")
	}
	if *pub == *priv {
		t.Fatal("public and private keys should differ")
	}
}

func TestGenerateKeyPair_Unique(t *testing.T) {
	pub1, _, _ := GenerateKeyPair()
	pub2, _, _ := GenerateKeyPair()
	if *pub1 == *pub2 {
		t.Fatal("two key pairs should have different public keys")
	}
}
