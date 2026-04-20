// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Shravanth. All rights reserved.

package service

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/vaultless/vaultless/internal/crypto"
	"github.com/vaultless/vaultless/internal/models"
)

const (
	auditMagicEncrypted = "ENC:"
)

// AuditWriter handles writing and querying encrypted NDJSON audit logs.
// Format: each line is either plaintext JSON (legacy) or "ENC:<base64>" (encrypted).
// Encrypted lines use AES-256-GCM with encrypt-then-MAC (HMAC over ciphertext).
type AuditWriter struct {
	path       string
	projectKey []byte
	hmacKey    []byte
}

func NewAuditWriter(path string, projectKey []byte) *AuditWriter {
	return &AuditWriter{
		path:       path,
		projectKey: projectKey,
		hmacKey:    crypto.DeriveAuditHMACKey(projectKey),
	}
}

// AuditQuery specifies filters for querying audit entries.
type AuditQuery struct {
	Key         string
	User        string
	Environment string
	From        *time.Time
	To          *time.Time
	Limit       int
	Offset      int
}

// Log writes an audit entry as encrypted NDJSON.
func (w *AuditWriter) Log(entry *models.AuditEntry) error {
	entry.ID = crypto.GenerateUUID()
	entry.Timestamp = timeNow()

	// Marshal entry without HMAC to compute signature
	entryForHMAC := *entry
	entryForHMAC.HMAC = ""
	jsonBytes, err := json.Marshal(&entryForHMAC)
	if err != nil {
		return fmt.Errorf("failed to marshal audit entry: %w", err)
	}

	// Compute HMAC over the JSON payload
	entry.HMAC = crypto.ComputeHMAC(w.hmacKey, jsonBytes)

	// Marshal again with HMAC included
	fullJSON, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("failed to marshal audit entry: %w", err)
	}

	// Encrypt the full JSON line
	ciphertext, nonce, err := crypto.Encrypt(w.projectKey, fullJSON)
	if err != nil {
		return fmt.Errorf("failed to encrypt audit entry: %w", err)
	}

	// Format: ENC:<nonce(12)><ciphertext> as hex
	encData := append(nonce, ciphertext...)
	line := auditMagicEncrypted + fmt.Sprintf("%x", encData)

	f, err := os.OpenFile(w.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("failed to open audit log: %w", err)
	}
	defer f.Close()

	if _, err := fmt.Fprintln(f, line); err != nil {
		return fmt.Errorf("failed to write audit entry: %w", err)
	}
	return nil
}

// Query reads and filters audit entries from the log file.
// Returns entries newest-first.
func (w *AuditWriter) Query(q *AuditQuery) ([]models.AuditEntry, error) {
	if q.Limit <= 0 {
		q.Limit = 50
	}

	entries, err := w.readAll()
	if err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		return nil, nil
	}

	// Reverse for newest-first
	for i, j := 0, len(entries)-1; i < j; i, j = i+1, j-1 {
		entries[i], entries[j] = entries[j], entries[i]
	}

	// Apply filters
	var filtered []models.AuditEntry
	for _, e := range entries {
		if q.Key != "" && e.Key != q.Key {
			continue
		}
		if q.User != "" && e.User != q.User {
			continue
		}
		if q.Environment != "" && e.Environment != q.Environment {
			continue
		}
		if q.From != nil && e.Timestamp.Before(*q.From) {
			continue
		}
		if q.To != nil && e.Timestamp.After(*q.To) {
			continue
		}
		filtered = append(filtered, e)
	}

	// Apply offset and limit
	if q.Offset >= len(filtered) {
		return nil, nil
	}
	filtered = filtered[q.Offset:]
	if len(filtered) > q.Limit {
		filtered = filtered[:q.Limit]
	}

	return filtered, nil
}

// Verify checks the HMAC integrity of all entries.
// Returns (valid count, invalid count, error).
func (w *AuditWriter) Verify() (int, int, error) {
	f, err := os.Open(w.path)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, 0, nil
		}
		return 0, 0, fmt.Errorf("failed to open audit log: %w", err)
	}
	defer f.Close()

	var valid, invalid int
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		var entry models.AuditEntry
		if len(line) > len(auditMagicEncrypted) && line[:len(auditMagicEncrypted)] == auditMagicEncrypted {
			hexData := line[len(auditMagicEncrypted):]
			data, err := hexDecode(hexData)
			if err != nil {
				invalid++
				continue
			}
			if len(data) < crypto.NonceSize {
				invalid++
				continue
			}
			nonce := data[:crypto.NonceSize]
			ciphertext := data[crypto.NonceSize:]
			plaintext, err := crypto.Decrypt(w.projectKey, ciphertext, nonce)
			if err != nil {
				invalid++
				continue
			}
			if err := json.Unmarshal(plaintext, &entry); err != nil {
				invalid++
				continue
			}
		} else {
			if err := json.Unmarshal([]byte(line), &entry); err != nil {
				invalid++
				continue
			}
		}

		savedHMAC := entry.HMAC
		entry.HMAC = ""
		jsonBytes, err := json.Marshal(&entry)
		if err != nil {
			invalid++
			continue
		}
		if crypto.VerifyHMAC(w.hmacKey, jsonBytes, savedHMAC) {
			valid++
		} else {
			invalid++
		}
	}

	if err := scanner.Err(); err != nil {
		return valid, invalid, fmt.Errorf("failed to read audit log: %w", err)
	}
	return valid, invalid, nil
}

// readAll reads all entries from the audit log, decrypting encrypted lines
// and parsing legacy plaintext lines for backwards compatibility.
func (w *AuditWriter) readAll() ([]models.AuditEntry, error) {
	f, err := os.Open(w.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to open audit log: %w", err)
	}
	defer f.Close()

	var entries []models.AuditEntry
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		var entry models.AuditEntry
		if len(line) > len(auditMagicEncrypted) && line[:len(auditMagicEncrypted)] == auditMagicEncrypted {
			// Encrypted line: decode hex and decrypt
			hexData := line[len(auditMagicEncrypted):]
			data, err := hexDecode(hexData)
			if err != nil {
				continue // skip malformed
			}
			if len(data) < crypto.NonceSize {
				continue
			}
			nonce := data[:crypto.NonceSize]
			ciphertext := data[crypto.NonceSize:]
			plaintext, err := crypto.Decrypt(w.projectKey, ciphertext, nonce)
			if err != nil {
				continue // skip entries we can't decrypt
			}
			if err := json.Unmarshal(plaintext, &entry); err != nil {
				continue
			}
		} else {
			// Legacy plaintext JSON
			if err := json.Unmarshal([]byte(line), &entry); err != nil {
				continue
			}
		}
		entries = append(entries, entry)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to read audit log: %w", err)
	}
	return entries, nil
}

// hexDecode decodes a hex string to bytes.
func hexDecode(s string) ([]byte, error) {
	if len(s)%2 != 0 {
		return nil, fmt.Errorf("odd-length hex string")
	}
	b := make([]byte, len(s)/2)
	for i := 0; i < len(s); i += 2 {
		hi := unhex(s[i])
		lo := unhex(s[i+1])
		if hi == 0xff || lo == 0xff {
			return nil, fmt.Errorf("invalid hex byte at %d", i)
		}
		b[i/2] = hi<<4 | lo
	}
	return b, nil
}

func unhex(c byte) byte {
	switch {
	case '0' <= c && c <= '9':
		return c - '0'
	case 'a' <= c && c <= 'f':
		return c - 'a' + 10
	case 'A' <= c && c <= 'F':
		return c - 'A' + 10
	default:
		return 0xff
	}
}
