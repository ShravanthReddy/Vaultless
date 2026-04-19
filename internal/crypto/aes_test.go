// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Shravanth. All rights reserved.

package crypto

import (
	"bytes"
	"testing"
)

func TestEncryptDecrypt_Roundtrip(t *testing.T) {
	key := make([]byte, KeySize)
	for i := range key {
		key[i] = byte(i)
	}

	plaintext := []byte("hello world secret value")

	ciphertext, nonce, err := Encrypt(key, plaintext)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	if len(nonce) != NonceSize {
		t.Fatalf("expected nonce size %d, got %d", NonceSize, len(nonce))
	}

	decrypted, err := Decrypt(key, ciphertext, nonce)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Fatalf("roundtrip failed: got %q, want %q", decrypted, plaintext)
	}
}

func TestEncrypt_InvalidKeySize(t *testing.T) {
	key := make([]byte, 16) // wrong size
	_, _, err := Encrypt(key, []byte("test"))
	if err == nil {
		t.Fatal("expected error for invalid key size")
	}
}

func TestDecrypt_InvalidKey(t *testing.T) {
	key1 := make([]byte, KeySize)
	key2 := make([]byte, KeySize)
	key2[0] = 1

	ciphertext, nonce, _ := Encrypt(key1, []byte("secret"))

	_, err := Decrypt(key2, ciphertext, nonce)
	if err == nil {
		t.Fatal("expected error for wrong key")
	}
}

func TestEncrypt_UniqueNonces(t *testing.T) {
	key := make([]byte, KeySize)
	plaintext := []byte("same data")

	_, nonce1, _ := Encrypt(key, plaintext)
	_, nonce2, _ := Encrypt(key, plaintext)

	if bytes.Equal(nonce1, nonce2) {
		t.Fatal("nonces should be unique")
	}
}

func TestEncrypt_EmptyPlaintext(t *testing.T) {
	key := make([]byte, KeySize)
	ciphertext, nonce, err := Encrypt(key, []byte{})
	if err != nil {
		t.Fatalf("Encrypt empty failed: %v", err)
	}

	decrypted, err := Decrypt(key, ciphertext, nonce)
	if err != nil {
		t.Fatalf("Decrypt empty failed: %v", err)
	}

	if len(decrypted) != 0 {
		t.Fatalf("expected empty, got %q", decrypted)
	}
}
