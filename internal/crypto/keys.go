// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Shravanth. All rights reserved.

package crypto

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
)

const (
	// projectKeyFileSize = salt(16) + nonce(12) + encrypted(32-byte key + 16-byte GCM tag)
	projectKeyFileSize = 16 + 12 + 48
)

// GenerateProjectKey generates a random 256-bit project key.
func GenerateProjectKey() ([]byte, error) {
	return GenerateRandomBytes(KeySize)
}

// StoreProjectKey encrypts and stores the project key on disk.
// Stored at ~/.vaultless/keys/<project-id>.key
func StoreProjectKey(projectID string, projectKey, masterKey []byte) error {
	keysDir := filepath.Join(globalDir(), "keys")
	if err := os.MkdirAll(keysDir, 0700); err != nil {
		return fmt.Errorf("failed to create keys directory: %w", err)
	}

	ciphertext, nonce, err := Encrypt(masterKey, projectKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt project key: %w", err)
	}

	// Generate a salt for the file (used for re-deriving in key rotation)
	salt, err := GenerateRandomBytes(16)
	if err != nil {
		return err
	}

	// File format: salt(16) || nonce(12) || ciphertext(48)
	data := make([]byte, 0, projectKeyFileSize)
	data = append(data, salt...)
	data = append(data, nonce...)
	data = append(data, ciphertext...)

	keyFile := filepath.Join(keysDir, projectID+".key")
	return os.WriteFile(keyFile, data, 0600)
}

// LoadProjectKey loads and decrypts the project key from disk.
func LoadProjectKey(projectID string, masterKey []byte) ([]byte, error) {
	keyFile := filepath.Join(globalDir(), "keys", projectID+".key")
	data, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read project key file: %w", err)
	}

	if len(data) != projectKeyFileSize {
		return nil, fmt.Errorf("invalid project key file size: expected %d, got %d", projectKeyFileSize, len(data))
	}

	// Parse: salt(16) | nonce(12) | ciphertext(48)
	nonce := data[16:28]
	ciphertext := data[28:]

	projectKey, err := Decrypt(masterKey, ciphertext, nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt project key (wrong master password?): %w", err)
	}

	return projectKey, nil
}

// ProjectKeyExists checks if a project key file exists.
func ProjectKeyExists(projectID string) bool {
	keyFile := filepath.Join(globalDir(), "keys", projectID+".key")
	_, err := os.Stat(keyFile)
	return err == nil
}

// CreateVerificationToken creates an encrypted verification token
// that can be used to verify the master password.
func CreateVerificationToken(masterKey []byte) (string, error) {
	plaintext := []byte("vaultless-verification-v1")
	ciphertext, nonce, err := Encrypt(masterKey, plaintext)
	if err != nil {
		return "", err
	}

	// Combine nonce + ciphertext and base64 encode
	combined := append(nonce, ciphertext...)
	return base64.StdEncoding.EncodeToString(combined), nil
}

// VerifyMasterKey verifies a master key against a stored verification token.
func VerifyMasterKey(masterKey []byte, verificationToken string) bool {
	combined, err := base64.StdEncoding.DecodeString(verificationToken)
	if err != nil {
		return false
	}

	if len(combined) < NonceSize {
		return false
	}

	nonce := combined[:NonceSize]
	ciphertext := combined[NonceSize:]

	plaintext, err := Decrypt(masterKey, ciphertext, nonce)
	if err != nil {
		return false
	}

	return string(plaintext) == "vaultless-verification-v1"
}

func globalDir() string {
	if home := os.Getenv("VAULTLESS_HOME"); home != "" {
		return home
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".vaultless")
}
