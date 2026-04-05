// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Shravanth. All rights reserved.

package crypto

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"

	"golang.org/x/crypto/nacl/box"
)

// GenerateKeyPair generates an X25519 key pair for team key exchange.
func GenerateKeyPair() (publicKey, privateKey *[32]byte, err error) {
	return box.GenerateKey(rand.Reader)
}

const (
	inviteSaltSize = 16
)

// CreateInviteBundle creates an encrypted bundle containing the project key.
// For v1, uses a simplified symmetric approach with a passphrase.
// Bundle format: salt(16) || nonce(12) || ciphertext (base64-encoded).
func CreateInviteBundle(projectKey []byte, passphrase string) (string, error) {
	// Generate random salt to prevent precomputation attacks
	salt, err := GenerateRandomBytes(inviteSaltSize)
	if err != nil {
		return "", fmt.Errorf("failed to generate salt: %w", err)
	}

	// Derive a bundle key from the passphrase with production-strength params
	bundleKey, _, err := DeriveKey([]byte(passphrase), salt, &DefaultArgon2Params)
	if err != nil {
		return "", fmt.Errorf("failed to derive bundle key: %w", err)
	}
	defer ZeroBytes(bundleKey)

	ciphertext, nonce, err := Encrypt(bundleKey, projectKey)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt project key for bundle: %w", err)
	}

	// Bundle = salt || nonce || ciphertext (base64-encoded)
	combined := make([]byte, 0, inviteSaltSize+NonceSize+len(ciphertext))
	combined = append(combined, salt...)
	combined = append(combined, nonce...)
	combined = append(combined, ciphertext...)
	return base64.StdEncoding.EncodeToString(combined), nil
}

// DecryptInviteBundle decrypts a bundle to retrieve the project key.
// Expected bundle format: salt(16) || nonce(12) || ciphertext (base64-encoded).
func DecryptInviteBundle(bundle, passphrase string) ([]byte, error) {
	combined, err := base64.StdEncoding.DecodeString(bundle)
	if err != nil {
		return nil, errors.New("invalid bundle format")
	}

	if len(combined) < inviteSaltSize+NonceSize {
		return nil, errors.New("invalid bundle: too short")
	}

	salt := combined[:inviteSaltSize]
	nonce := combined[inviteSaltSize : inviteSaltSize+NonceSize]
	ciphertext := combined[inviteSaltSize+NonceSize:]

	bundleKey, _, err := DeriveKey([]byte(passphrase), salt, &DefaultArgon2Params)
	if err != nil {
		return nil, fmt.Errorf("failed to derive bundle key: %w", err)
	}
	defer ZeroBytes(bundleKey)

	projectKey, err := Decrypt(bundleKey, ciphertext, nonce)
	if err != nil {
		return nil, errors.New("failed to decrypt bundle: wrong passphrase?")
	}

	return projectKey, nil
}
