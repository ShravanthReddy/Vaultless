// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Shravanth. All rights reserved.

//go:build !windows

package sync

import (
	"fmt"
	"os"
	"syscall"
)

// LockExclusive acquires an exclusive lock (LOCK_EX) for push operations.
// Blocks until the lock is acquired.
func (fl *FileLock) LockExclusive() error {
	f, err := os.OpenFile(fl.path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return fmt.Errorf("failed to open lock file: %w", err)
	}
	fl.file = f

	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		fl.file = nil
		return fmt.Errorf("failed to acquire exclusive lock: %w", err)
	}
	return nil
}

// LockShared acquires a shared lock (LOCK_SH) for pull operations.
// Blocks until the lock is acquired.
func (fl *FileLock) LockShared() error {
	f, err := os.OpenFile(fl.path, os.O_CREATE|os.O_RDONLY, 0600)
	if err != nil {
		return fmt.Errorf("failed to open lock file: %w", err)
	}
	fl.file = f

	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_SH); err != nil {
		f.Close()
		fl.file = nil
		return fmt.Errorf("failed to acquire shared lock: %w", err)
	}
	return nil
}

// TryLockExclusive attempts a non-blocking exclusive lock.
// Returns false if the lock could not be acquired immediately.
func (fl *FileLock) TryLockExclusive() (bool, error) {
	f, err := os.OpenFile(fl.path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return false, fmt.Errorf("failed to open lock file: %w", err)
	}
	fl.file = f

	err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	if err != nil {
		f.Close()
		fl.file = nil
		if err == syscall.EWOULDBLOCK {
			return false, nil
		}
		return false, fmt.Errorf("failed to try exclusive lock: %w", err)
	}
	return true, nil
}

// Unlock releases the file lock and closes the underlying file.
func (fl *FileLock) Unlock() error {
	if fl.file == nil {
		return nil
	}

	err := syscall.Flock(int(fl.file.Fd()), syscall.LOCK_UN)
	closeErr := fl.file.Close()
	fl.file = nil

	if err != nil {
		return fmt.Errorf("failed to unlock: %w", err)
	}
	return closeErr
}
