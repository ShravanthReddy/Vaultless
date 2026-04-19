// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Shravanth. All rights reserved.

package crypto

import "testing"

func TestZeroBytes(t *testing.T) {
	data := []byte{1, 2, 3, 4, 5}
	ZeroBytes(data)

	for i, b := range data {
		if b != 0 {
			t.Fatalf("byte %d not zeroed: got %d", i, b)
		}
	}
}

func TestSecureBuffer_Close(t *testing.T) {
	data := []byte{10, 20, 30}
	buf := NewSecureBuffer(data)
	buf.Close()

	if buf.Data != nil {
		t.Fatal("Data should be nil after Close")
	}

	// Check original slice is zeroed
	for i, b := range data {
		if b != 0 {
			t.Fatalf("byte %d not zeroed: got %d", i, b)
		}
	}
}
