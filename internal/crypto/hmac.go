// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Shravanth. All rights reserved.

package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"io"

	"golang.org/x/crypto/hkdf"
)

// ComputeHMAC computes HMAC-SHA256 of data with key, returns base64-encoded result.
func ComputeHMAC(key, data []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

// VerifyHMAC verifies an HMAC-SHA256 in constant time.
func VerifyHMAC(key, data []byte, expected string) bool {
	expectedBytes, err := base64.StdEncoding.DecodeString(expected)
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return hmac.Equal(mac.Sum(nil), expectedBytes)
}

// DeriveAuditHMACKey derives the audit HMAC key from the project key using HKDF-SHA256.
func DeriveAuditHMACKey(projectKey []byte) []byte {
	reader := hkdf.New(sha256.New, projectKey, nil, []byte("vaultless-audit-hmac-v1"))
	key := make([]byte, 32)
	io.ReadFull(reader, key)
	return key
}

// HashSHA256 returns the SHA-256 hash of data.
func HashSHA256(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}
