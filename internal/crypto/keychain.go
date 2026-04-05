// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Shravanth. All rights reserved.

package crypto

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"time"

	"github.com/zalando/go-keyring"
)

const (
	keychainService = "vaultless"
)

// Keychain provides OS-native secure credential storage.
type Keychain interface {
	Store(service, account string, secret []byte) error
	Retrieve(service, account string) ([]byte, error)
	Delete(service, account string) error
	Available() bool
}

// SessionData stored in OS keychain (or fallback file).
type SessionData struct {
	ProjectID string    `json:"project_id"`
	MasterKey []byte    `json:"master_key"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// NewKeychain returns the platform-appropriate keychain.
// Falls back to encrypted file storage if no keychain is available.
func NewKeychain() Keychain {
	kc := &osKeychain{}
	if kc.Available() {
		return kc
	}
	return &fallbackKeychain{}
}

// osKeychain uses the OS keychain via go-keyring.
type osKeychain struct{}

func (k *osKeychain) Available() bool {
	// Test if keychain is accessible by attempting a no-op
	err := keyring.Set("vaultless-test", "availability-check", "test")
	if err != nil {
		return false
	}
	_ = keyring.Delete("vaultless-test", "availability-check")
	return true
}

func (k *osKeychain) Store(service, account string, secret []byte) error {
	return keyring.Set(service, account, string(secret))
}

func (k *osKeychain) Retrieve(service, account string) ([]byte, error) {
	val, err := keyring.Get(service, account)
	if err != nil {
		return nil, err
	}
	return []byte(val), nil
}

func (k *osKeychain) Delete(service, account string) error {
	return keyring.Delete(service, account)
}

// fallbackKeychain stores sessions encrypted with a machine-entropy-derived key.
// Per ARCHITECTURE.md Section 7.6, the encryption key is derived from
// SHA-256(machine-id || username || "vaultless-session").
type fallbackKeychain struct{}

func (k *fallbackKeychain) Available() bool {
	return true
}

func (k *fallbackKeychain) Store(service, account string, secret []byte) error {
	dir := filepath.Join(globalDir(), "sessions")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}

	encKey := deriveMachineKey()
	ciphertext, nonce, err := Encrypt(encKey, secret)
	if err != nil {
		return fmt.Errorf("failed to encrypt session data: %w", err)
	}
	ZeroBytes(encKey)

	// File format: nonce(12) || ciphertext
	data := append(nonce, ciphertext...)
	file := filepath.Join(dir, fmt.Sprintf("%s_%s", service, account))
	return os.WriteFile(file, data, 0600)
}

func (k *fallbackKeychain) Retrieve(service, account string) ([]byte, error) {
	file := filepath.Join(globalDir(), "sessions", fmt.Sprintf("%s_%s", service, account))
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}

	if len(data) < NonceSize {
		return nil, fmt.Errorf("invalid session file: too short")
	}

	nonce := data[:NonceSize]
	ciphertext := data[NonceSize:]

	encKey := deriveMachineKey()
	plaintext, err := Decrypt(encKey, ciphertext, nonce)
	ZeroBytes(encKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt session data: %w", err)
	}

	return plaintext, nil
}

func (k *fallbackKeychain) Delete(service, account string) error {
	file := filepath.Join(globalDir(), "sessions", fmt.Sprintf("%s_%s", service, account))
	return os.Remove(file)
}

// deriveMachineKey derives a 32-byte encryption key from machine-specific entropy.
// Uses SHA-256(machine-id || username || "vaultless-session").
func deriveMachineKey() []byte {
	h := sha256.New()

	// Machine ID (Linux: /etc/machine-id, fallback to hostname)
	if machineID, err := os.ReadFile("/etc/machine-id"); err == nil {
		h.Write([]byte(strings.TrimSpace(string(machineID))))
	} else if hostname, err := os.Hostname(); err == nil {
		h.Write([]byte(hostname))
	}

	// Username
	if u, err := user.Current(); err == nil {
		h.Write([]byte(u.Username))
	}

	h.Write([]byte("vaultless-session"))

	key := h.Sum(nil) // 32 bytes (SHA-256)
	return key
}

// StoreSession stores session data in the keychain.
func StoreSession(kc Keychain, projectID string, session *SessionData) error {
	data, err := json.Marshal(session)
	if err != nil {
		return err
	}
	return kc.Store(keychainService, projectID, data)
}

// LoadSession loads session data from the keychain.
func LoadSession(kc Keychain, projectID string) (*SessionData, error) {
	data, err := kc.Retrieve(keychainService, projectID)
	if err != nil {
		return nil, err
	}

	var session SessionData
	if err := json.Unmarshal(data, &session); err != nil {
		return nil, err
	}

	if time.Now().After(session.ExpiresAt) {
		_ = kc.Delete(keychainService, projectID)
		return nil, fmt.Errorf("session expired")
	}

	return &session, nil
}

// DeleteSession removes session data from the keychain.
func DeleteSession(kc Keychain, projectID string) error {
	return kc.Delete(keychainService, projectID)
}
