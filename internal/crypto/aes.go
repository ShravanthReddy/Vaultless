// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Shravanth. All rights reserved.

package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
)

const (
	NonceSize = 12 // 96 bits per NIST recommendation for GCM
	KeySize   = 32 // 256 bits
)

// Encrypt encrypts plaintext using AES-256-GCM with a random nonce.
// Returns (ciphertext, nonce, error). The ciphertext includes the GCM auth tag.
func Encrypt(key, plaintext []byte) (ciphertext, nonce []byte, err error) {
	if len(key) != KeySize {
		return nil, nil, errors.New("invalid key size: expected 32 bytes")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}

	nonce = make([]byte, NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, err
	}

	ciphertext = gcm.Seal(nil, nonce, plaintext, nil)
	return ciphertext, nonce, nil
}

// Decrypt decrypts ciphertext using AES-256-GCM.
// Returns the plaintext or an error if authentication fails.
func Decrypt(key, ciphertext, nonce []byte) (plaintext []byte, err error) {
	if len(key) != KeySize {
		return nil, errors.New("invalid key size: expected 32 bytes")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	plaintext, err = gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, errors.New("decryption failed: invalid key or corrupted data")
	}

	return plaintext, nil
}
