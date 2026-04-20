// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Shravanth. All rights reserved.

package sync

import (
	"fmt"
	"os"
	"path/filepath"
)

// SyncBackend defines the interface for sync operations.
type SyncBackend interface {
	Push(data []byte) error
	Pull() ([]byte, error)
	Hash() (string, error)
}

// GitBackend implements SyncBackend for Git repositories.
type GitBackend struct {
	remote    string
	projectID string
	branch    string
}

func NewGitBackend(remote, projectID, branch string) *GitBackend {
	return &GitBackend{
		remote:    remote,
		projectID: projectID,
		branch:    branch,
	}
}

func (g *GitBackend) Push(data []byte) error {
	return fmt.Errorf("git sync not yet implemented")
}

func (g *GitBackend) Pull() ([]byte, error) {
	return nil, fmt.Errorf("git sync not yet implemented")
}

func (g *GitBackend) Hash() (string, error) {
	return "", fmt.Errorf("git sync not yet implemented")
}

// FilesystemBackend implements SyncBackend for local filesystem sync.
type FilesystemBackend struct {
	basePath  string
	projectID string
}

func NewFilesystemBackend(basePath, projectID string) *FilesystemBackend {
	return &FilesystemBackend{
		basePath:  basePath,
		projectID: projectID,
	}
}

func (f *FilesystemBackend) syncPath() string {
	return filepath.Join(f.basePath, f.projectID+".vaultless")
}

func (f *FilesystemBackend) lockPath() string {
	return filepath.Join(f.basePath, f.projectID+".lock")
}

func (f *FilesystemBackend) Push(data []byte) error {
	lock := NewFileLock(f.lockPath())
	if err := lock.LockExclusive(); err != nil {
		return fmt.Errorf("failed to acquire push lock: %w", err)
	}
	defer lock.Unlock()

	if err := os.MkdirAll(f.basePath, 0700); err != nil {
		return fmt.Errorf("failed to create sync directory: %w", err)
	}
	return os.WriteFile(f.syncPath(), data, 0600)
}

func (f *FilesystemBackend) Pull() ([]byte, error) {
	lock := NewFileLock(f.lockPath())
	if err := lock.LockShared(); err != nil {
		return nil, fmt.Errorf("failed to acquire pull lock: %w", err)
	}
	defer lock.Unlock()

	data, err := os.ReadFile(f.syncPath())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	return data, nil
}

func (f *FilesystemBackend) Hash() (string, error) {
	data, err := f.Pull()
	if err != nil {
		return "", err
	}
	if data == nil {
		return "", nil
	}
	return fmt.Sprintf("%x", data[:min(32, len(data))]), nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
