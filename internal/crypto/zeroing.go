// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Shravanth. All rights reserved.

package crypto

// ZeroBytes overwrites a byte slice with zeros.
// Used to clear sensitive data (keys, plaintext secrets) from memory.
func ZeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// SecureBuffer wraps a byte slice and zeros it when Close() is called.
// Use with defer: buf := NewSecureBuffer(data); defer buf.Close()
type SecureBuffer struct {
	Data []byte
}

func NewSecureBuffer(data []byte) *SecureBuffer {
	return &SecureBuffer{Data: data}
}

func (sb *SecureBuffer) Close() {
	ZeroBytes(sb.Data)
	sb.Data = nil
}
