// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Shravanth. All rights reserved.

package sync

import "os"

// FileLock provides advisory file locking across platforms.
// Locking behavior is implemented in lock_unix.go and lock_windows.go.
type FileLock struct {
	path string
	file *os.File
}

// NewFileLock creates a new file lock at the given path.
// The lock file is created if it does not exist.
func NewFileLock(path string) *FileLock {
	return &FileLock{path: path}
}
