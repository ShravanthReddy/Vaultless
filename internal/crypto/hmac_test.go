// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Shravanth. All rights reserved.

package crypto

import "testing"

func TestHMAC_Roundtrip(t *testing.T) {
	key := []byte("test-hmac-key-32-bytes-long!!!!!")
	data := []byte(`{"operation":"set","key":"API_KEY"}`)

	hmac := ComputeHMAC(key, data)
	if hmac == "" {
		t.Fatal("HMAC should not be empty")
	}

	if !VerifyHMAC(key, data, hmac) {
		t.Fatal("HMAC verification failed")
	}
}

func TestHMAC_TamperDetection(t *testing.T) {
	key := []byte("test-hmac-key-32-bytes-long!!!!!")
	data := []byte(`{"operation":"set","key":"API_KEY"}`)

	hmac := ComputeHMAC(key, data)

	tampered := []byte(`{"operation":"set","key":"HACKED"}`)
	if VerifyHMAC(key, tampered, hmac) {
		t.Fatal("HMAC should detect tampering")
	}
}
