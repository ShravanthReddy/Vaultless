// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Shravanth. All rights reserved.

package service

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
)

var backupMagic = []byte("VLTBAK01")

// BackupService handles creating and restoring encrypted backups.
type BackupService struct {
	projectPath string
	projectID   string
}

func NewBackupService(projectPath, projectID string) *BackupService {
	return &BackupService{
		projectPath: projectPath,
		projectID:   projectID,
	}
}

// Create creates a backup archive of the project.
func (s *BackupService) Create(outputPath string) error {
	dbPath := filepath.Join(s.projectPath, "secrets.db")
	dbData, err := os.ReadFile(dbPath)
	if err != nil {
		return fmt.Errorf("failed to read database: %w", err)
	}

	configData, _ := os.ReadFile(filepath.Join(s.projectPath, "config.toml"))
	auditData, _ := os.ReadFile(filepath.Join(s.projectPath, "audit.log"))

	// Format: magic(8) || dbLen(4) || db || configLen(4) || config || auditLen(4) || audit || sha256(32)
	buf := make([]byte, 0, len(backupMagic)+4+len(dbData)+4+len(configData)+4+len(auditData)+32)
	buf = append(buf, backupMagic...)
	buf = binary.BigEndian.AppendUint32(buf, uint32(len(dbData)))
	buf = append(buf, dbData...)
	buf = binary.BigEndian.AppendUint32(buf, uint32(len(configData)))
	buf = append(buf, configData...)
	buf = binary.BigEndian.AppendUint32(buf, uint32(len(auditData)))
	buf = append(buf, auditData...)

	hash := sha256.Sum256(buf)
	buf = append(buf, hash[:]...)

	return os.WriteFile(outputPath, buf, 0600)
}

// Restore restores a backup archive to the project path.
func (s *BackupService) Restore(inputPath string) error {
	data, err := os.ReadFile(inputPath)
	if err != nil {
		return fmt.Errorf("failed to read backup: %w", err)
	}

	if len(data) < len(backupMagic)+32 {
		return fmt.Errorf("invalid backup: file too short")
	}

	// Verify magic
	if string(data[:len(backupMagic)]) != string(backupMagic) {
		return fmt.Errorf("invalid backup: wrong magic bytes")
	}

	// Verify checksum
	payload := data[:len(data)-32]
	storedHash := data[len(data)-32:]
	computed := sha256.Sum256(payload)
	for i := 0; i < 32; i++ {
		if computed[i] != storedHash[i] {
			return fmt.Errorf("backup integrity check failed: data has been tampered with")
		}
	}

	// Parse sections
	pos := len(backupMagic)

	if pos+4 > len(payload) {
		return fmt.Errorf("invalid backup: truncated db length")
	}
	dbLen := int(binary.BigEndian.Uint32(payload[pos : pos+4]))
	pos += 4
	if pos+dbLen > len(payload) {
		return fmt.Errorf("invalid backup: truncated db data")
	}
	dbData := payload[pos : pos+dbLen]
	pos += dbLen

	if pos+4 > len(payload) {
		return fmt.Errorf("invalid backup: truncated config length")
	}
	configLen := int(binary.BigEndian.Uint32(payload[pos : pos+4]))
	pos += 4
	if pos+configLen > len(payload) {
		return fmt.Errorf("invalid backup: truncated config data")
	}
	configData := payload[pos : pos+configLen]
	pos += configLen

	if pos+4 > len(payload) {
		return fmt.Errorf("invalid backup: truncated audit length")
	}
	auditLen := int(binary.BigEndian.Uint32(payload[pos : pos+4]))
	pos += 4
	if pos+auditLen > len(payload) {
		return fmt.Errorf("invalid backup: truncated audit data")
	}
	auditData := payload[pos : pos+auditLen]

	// Write restored files
	if err := os.MkdirAll(s.projectPath, 0700); err != nil {
		return err
	}

	if err := os.WriteFile(filepath.Join(s.projectPath, "secrets.db"), dbData, 0600); err != nil {
		return fmt.Errorf("failed to restore database: %w", err)
	}

	if len(configData) > 0 {
		if err := os.WriteFile(filepath.Join(s.projectPath, "config.toml"), configData, 0600); err != nil {
			return fmt.Errorf("failed to restore config: %w", err)
		}
	}

	if len(auditData) > 0 {
		if err := os.WriteFile(filepath.Join(s.projectPath, "audit.log"), auditData, 0600); err != nil {
			return fmt.Errorf("failed to restore audit log: %w", err)
		}
	}

	return nil
}
