// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Shravanth. All rights reserved.

package crypto

import (
	"testing"
)

func TestRotateProjectKey(t *testing.T) {
	oldKey, err := GenerateProjectKey()
	if err != nil {
		t.Fatalf("GenerateProjectKey: %v", err)
	}

	newKey, event, err := RotateProjectKey(oldKey, "admin@example.com", 10)
	if err != nil {
		t.Fatalf("RotateProjectKey: %v", err)
	}

	if len(newKey) != KeySize {
		t.Fatalf("expected new key size %d, got %d", KeySize, len(newKey))
	}

	// New key should be different from old key
	same := true
	for i := range newKey {
		if newKey[i] != oldKey[i] {
			same = false
			break
		}
	}
	if same {
		t.Fatal("new key should differ from old key")
	}

	if event.ID == "" {
		t.Fatal("expected rotation event ID")
	}
	if event.RotatedBy != "admin@example.com" {
		t.Fatalf("expected rotated_by 'admin@example.com', got %q", event.RotatedBy)
	}
	if event.SecretsCount != 10 {
		t.Fatalf("expected secrets_count 10, got %d", event.SecretsCount)
	}
	if event.Signature == "" {
		t.Fatal("expected signed rotation event")
	}
	if event.OldKeyHash == "" || event.NewKeyHash == "" {
		t.Fatal("expected key hashes in event")
	}
}

func TestVerifyRotationEvent(t *testing.T) {
	oldKey, _ := GenerateProjectKey()
	newKey, event, _ := RotateProjectKey(oldKey, "admin@example.com", 5)

	// Verify with correct key should succeed
	if !VerifyRotationEvent(event, newKey) {
		t.Fatal("expected verification to succeed with correct key")
	}

	// Verify with wrong key should fail
	wrongKey, _ := GenerateProjectKey()
	if VerifyRotationEvent(event, wrongKey) {
		t.Fatal("expected verification to fail with wrong key")
	}

	// Verify with old key should fail (signed with new key)
	if VerifyRotationEvent(event, oldKey) {
		t.Fatal("expected verification to fail with old key")
	}
}

func TestVerifyRotationEvent_Tampered(t *testing.T) {
	oldKey, _ := GenerateProjectKey()
	newKey, event, _ := RotateProjectKey(oldKey, "admin@example.com", 5)

	// Tamper with the event
	event.SecretsCount = 999
	if VerifyRotationEvent(event, newKey) {
		t.Fatal("expected verification to fail with tampered event")
	}
}

func TestReEncryptSecret(t *testing.T) {
	oldKey, _ := GenerateProjectKey()
	newKey, _ := GenerateProjectKey()

	// Encrypt with old key
	plaintext := []byte("super-secret-value")
	ciphertext, nonce, err := Encrypt(oldKey, plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// Re-encrypt
	newCiphertext, newNonce, err := ReEncryptSecret(oldKey, newKey, ciphertext, nonce)
	if err != nil {
		t.Fatalf("ReEncryptSecret: %v", err)
	}

	// Decrypt with new key should yield original plaintext
	decrypted, err := Decrypt(newKey, newCiphertext, newNonce)
	if err != nil {
		t.Fatalf("Decrypt with new key: %v", err)
	}
	if string(decrypted) != "super-secret-value" {
		t.Fatalf("expected 'super-secret-value', got %q", string(decrypted))
	}

	// Decrypt with old key should fail
	_, err = Decrypt(oldKey, newCiphertext, newNonce)
	if err == nil {
		t.Fatal("expected decryption with old key to fail")
	}
}

func TestReEncryptSecret_WrongOldKey(t *testing.T) {
	realKey, _ := GenerateProjectKey()
	wrongKey, _ := GenerateProjectKey()
	newKey, _ := GenerateProjectKey()

	ciphertext, nonce, _ := Encrypt(realKey, []byte("secret"))

	_, _, err := ReEncryptSecret(wrongKey, newKey, ciphertext, nonce)
	if err == nil {
		t.Fatal("expected error when re-encrypting with wrong old key")
	}
}

func TestCreateRotationBundle(t *testing.T) {
	key, _ := GenerateProjectKey()
	bundle, err := CreateRotationBundle(key, "test-passphrase-123")
	if err != nil {
		t.Fatalf("CreateRotationBundle: %v", err)
	}
	if bundle == "" {
		t.Fatal("expected non-empty bundle")
	}

	// Decrypt the bundle
	recovered, err := DecryptInviteBundle(bundle, "test-passphrase-123")
	if err != nil {
		t.Fatalf("DecryptInviteBundle: %v", err)
	}
	if len(recovered) != KeySize {
		t.Fatalf("expected key size %d, got %d", KeySize, len(recovered))
	}
	for i := range key {
		if key[i] != recovered[i] {
			t.Fatal("recovered key does not match original")
		}
	}
}
