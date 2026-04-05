// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Shravanth. All rights reserved.

package crypto

import (
	"crypto/rand"

	"golang.org/x/crypto/argon2"
)

// Argon2Params matches SPEC §NFR-SEC-1.
type Argon2Params struct {
	Memory      uint32 // 64 * 1024 (64 MB)
	Iterations  uint32 // 3
	Parallelism uint8  // 4
	SaltLength  uint32 // 16 bytes
	KeyLength   uint32 // 32 bytes (256 bits)
}

var DefaultArgon2Params = Argon2Params{
	Memory:      64 * 1024,
	Iterations:  3,
	Parallelism: 4,
	SaltLength:  16,
	KeyLength:   32,
}

// TestArgon2Params uses reduced parameters for fast test execution.
var TestArgon2Params = Argon2Params{
	Memory:      1024,
	Iterations:  1,
	Parallelism: 1,
	SaltLength:  16,
	KeyLength:   32,
}

// DeriveKey derives an encryption key from a master password using Argon2id.
// If salt is nil, a random salt is generated.
// Returns the derived key and the salt used. When a non-nil salt is provided,
// the returned usedSalt is the same slice (not a copy).
func DeriveKey(password []byte, salt []byte, params *Argon2Params) (key []byte, usedSalt []byte, err error) {
	if params == nil {
		params = &DefaultArgon2Params
	}

	if salt == nil {
		salt = make([]byte, params.SaltLength)
		if _, err := rand.Read(salt); err != nil {
			return nil, nil, err
		}
	}

	key = argon2.IDKey(
		password,
		salt,
		params.Iterations,
		params.Memory,
		params.Parallelism,
		params.KeyLength,
	)

	return key, salt, nil
}
