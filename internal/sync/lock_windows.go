// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Shravanth. All rights reserved.

//go:build windows

package sync

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

// lockRegion covers the entire conceptual file range. Windows advisory locks
// operate on byte ranges, so we lock from offset 0 with the maximum length.
const (
	lockBytesLow  uint32 = 0xFFFFFFFF
	lockBytesHigh uint32 = 0xFFFFFFFF
)

// LockExclusive acquires an exclusive lock for push operations.
// Blocks until the lock is acquired.
func (fl *FileLock) LockExclusive() error {
	f, err := os.OpenFile(fl.path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return fmt.Errorf("failed to open lock file: %w", err)
	}
	fl.file = f

	ol := &windows.Overlapped{}
	if err := windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK, 0, lockBytesLow, lockBytesHigh, ol); err != nil {
		f.Close()
		fl.file = nil
		return fmt.Errorf("failed to acquire exclusive lock: %w", err)
	}
	return nil
}

// LockShared acquires a shared lock for pull operations.
// Blocks until the lock is acquired.
func (fl *FileLock) LockShared() error {
	// Windows requires GENERIC_READ access for shared locks via LockFileEx,
	// and the handle must allow writing for exclusive locks. O_RDWR satisfies
	// both cases and keeps the semantics aligned with the Unix implementation.
	f, err := os.OpenFile(fl.path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return fmt.Errorf("failed to open lock file: %w", err)
	}
	fl.file = f

	ol := &windows.Overlapped{}
	if err := windows.LockFileEx(windows.Handle(f.Fd()), 0, 0, lockBytesLow, lockBytesHigh, ol); err != nil {
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

	ol := &windows.Overlapped{}
	flags := uint32(windows.LOCKFILE_EXCLUSIVE_LOCK | windows.LOCKFILE_FAIL_IMMEDIATELY)
	err = windows.LockFileEx(windows.Handle(f.Fd()), flags, 0, lockBytesLow, lockBytesHigh, ol)
	if err != nil {
		f.Close()
		fl.file = nil
		if errors.Is(err, windows.ERROR_LOCK_VIOLATION) || errors.Is(err, windows.ERROR_IO_PENDING) {
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

	ol := &windows.Overlapped{}
	err := windows.UnlockFileEx(windows.Handle(fl.file.Fd()), 0, lockBytesLow, lockBytesHigh, ol)
	closeErr := fl.file.Close()
	fl.file = nil

	if err != nil {
		return fmt.Errorf("failed to unlock: %w", err)
	}
	return closeErr
}
