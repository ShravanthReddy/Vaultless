// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Shravanth. All rights reserved.

package crypto

import (
	"encoding/json"
	"fmt"
	"time"
)

// RotationEvent records a key rotation for audit purposes.
type RotationEvent struct {
	ID           string    `json:"id"`
	Timestamp    time.Time `json:"timestamp"`
	RotatedBy    string    `json:"rotated_by"`
	OldKeyHash   string    `json:"old_key_hash"`
	NewKeyHash   string    `json:"new_key_hash"`
	SecretsCount int       `json:"secrets_count"`
	Signature    string    `json:"signature"`
}

// RotateProjectKey generates a new project key and returns it along with a signed rotation event.
// The caller is responsible for re-encrypting secrets and storing the new key.
func RotateProjectKey(oldKey []byte, rotatedBy string, secretsCount int) (newKey []byte, event *RotationEvent, err error) {
	newKey, err = GenerateProjectKey()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate new project key: %w", err)
	}

	event = &RotationEvent{
		ID:           GenerateUUID(),
		Timestamp:    time.Now().UTC(),
		RotatedBy:    rotatedBy,
		OldKeyHash:   fmt.Sprintf("%x", HashSHA256(oldKey)),
		NewKeyHash:   fmt.Sprintf("%x", HashSHA256(newKey)),
		SecretsCount: secretsCount,
	}

	// Sign the event with the new key
	eventBytes, err := json.Marshal(struct {
		ID           string    `json:"id"`
		Timestamp    time.Time `json:"timestamp"`
		RotatedBy    string    `json:"rotated_by"`
		OldKeyHash   string    `json:"old_key_hash"`
		NewKeyHash   string    `json:"new_key_hash"`
		SecretsCount int       `json:"secrets_count"`
	}{
		ID:           event.ID,
		Timestamp:    event.Timestamp,
		RotatedBy:    event.RotatedBy,
		OldKeyHash:   event.OldKeyHash,
		NewKeyHash:   event.NewKeyHash,
		SecretsCount: event.SecretsCount,
	})
	if err != nil {
		ZeroBytes(newKey)
		return nil, nil, fmt.Errorf("failed to marshal rotation event: %w", err)
	}

	hmacKey := DeriveAuditHMACKey(newKey)
	event.Signature = ComputeHMAC(hmacKey, eventBytes)
	ZeroBytes(hmacKey)

	return newKey, event, nil
}

// VerifyRotationEvent verifies the signature on a rotation event.
func VerifyRotationEvent(event *RotationEvent, key []byte) bool {
	eventBytes, err := json.Marshal(struct {
		ID           string    `json:"id"`
		Timestamp    time.Time `json:"timestamp"`
		RotatedBy    string    `json:"rotated_by"`
		OldKeyHash   string    `json:"old_key_hash"`
		NewKeyHash   string    `json:"new_key_hash"`
		SecretsCount int       `json:"secrets_count"`
	}{
		ID:           event.ID,
		Timestamp:    event.Timestamp,
		RotatedBy:    event.RotatedBy,
		OldKeyHash:   event.OldKeyHash,
		NewKeyHash:   event.NewKeyHash,
		SecretsCount: event.SecretsCount,
	})
	if err != nil {
		return false
	}

	hmacKey := DeriveAuditHMACKey(key)
	defer ZeroBytes(hmacKey)
	return VerifyHMAC(hmacKey, eventBytes, event.Signature)
}

// ReEncryptSecret decrypts a secret with the old key and re-encrypts with the new key.
// Returns new ciphertext and nonce.
func ReEncryptSecret(oldKey, newKey, ciphertext, nonce []byte) (newCiphertext, newNonce []byte, err error) {
	plaintext, err := Decrypt(oldKey, ciphertext, nonce)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decrypt with old key: %w", err)
	}
	defer ZeroBytes(plaintext)

	newCiphertext, newNonce, err = Encrypt(newKey, plaintext)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encrypt with new key: %w", err)
	}
	return newCiphertext, newNonce, nil
}

// CreateRotationBundle creates an invite bundle containing the new project key,
// encrypted with a passphrase, for distributing to team members.
func CreateRotationBundle(newKey []byte, passphrase string) (string, error) {
	return CreateInviteBundle(newKey, passphrase)
}
