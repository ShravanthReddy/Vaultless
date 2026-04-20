// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Shravanth. All rights reserved.

package sync

import (
	"path/filepath"
	"testing"
)

func TestFileLock_ExclusiveLock(t *testing.T) {
	tmpDir := t.TempDir()
	lockPath := filepath.Join(tmpDir, "test.lock")

	fl := NewFileLock(lockPath)
	if err := fl.LockExclusive(); err != nil {
		t.Fatalf("LockExclusive: %v", err)
	}
	if err := fl.Unlock(); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
}

func TestFileLock_SharedLock(t *testing.T) {
	tmpDir := t.TempDir()
	lockPath := filepath.Join(tmpDir, "test.lock")

	fl := NewFileLock(lockPath)
	if err := fl.LockShared(); err != nil {
		t.Fatalf("LockShared: %v", err)
	}
	if err := fl.Unlock(); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
}

func TestFileLock_MultipleSharedLocks(t *testing.T) {
	tmpDir := t.TempDir()
	lockPath := filepath.Join(tmpDir, "test.lock")

	fl1 := NewFileLock(lockPath)
	fl2 := NewFileLock(lockPath)

	if err := fl1.LockShared(); err != nil {
		t.Fatalf("LockShared 1: %v", err)
	}
	// Second shared lock should succeed while first is held
	if err := fl2.LockShared(); err != nil {
		t.Fatalf("LockShared 2: %v", err)
	}

	if err := fl1.Unlock(); err != nil {
		t.Fatalf("Unlock 1: %v", err)
	}
	if err := fl2.Unlock(); err != nil {
		t.Fatalf("Unlock 2: %v", err)
	}
}

func TestFileLock_TryExclusiveBlocked(t *testing.T) {
	tmpDir := t.TempDir()
	lockPath := filepath.Join(tmpDir, "test.lock")

	fl1 := NewFileLock(lockPath)
	fl2 := NewFileLock(lockPath)

	if err := fl1.LockExclusive(); err != nil {
		t.Fatalf("LockExclusive: %v", err)
	}

	// Try non-blocking exclusive should fail while first is held
	acquired, err := fl2.TryLockExclusive()
	if err != nil {
		t.Fatalf("TryLockExclusive: %v", err)
	}
	if acquired {
		t.Fatal("expected TryLockExclusive to fail while exclusive lock is held")
	}

	if err := fl1.Unlock(); err != nil {
		t.Fatalf("Unlock: %v", err)
	}

	// Now it should succeed
	acquired, err = fl2.TryLockExclusive()
	if err != nil {
		t.Fatalf("TryLockExclusive after unlock: %v", err)
	}
	if !acquired {
		t.Fatal("expected TryLockExclusive to succeed after unlock")
	}
	if err := fl2.Unlock(); err != nil {
		t.Fatalf("Unlock 2: %v", err)
	}
}

func TestFileLock_UnlockWithoutLock(t *testing.T) {
	tmpDir := t.TempDir()
	lockPath := filepath.Join(tmpDir, "test.lock")

	fl := NewFileLock(lockPath)
	// Unlock without holding a lock should be safe (no-op)
	if err := fl.Unlock(); err != nil {
		t.Fatalf("Unlock without lock: %v", err)
	}
}

func TestFileLock_ReacquireAfterUnlock(t *testing.T) {
	tmpDir := t.TempDir()
	lockPath := filepath.Join(tmpDir, "test.lock")

	fl := NewFileLock(lockPath)
	if err := fl.LockExclusive(); err != nil {
		t.Fatalf("LockExclusive 1: %v", err)
	}
	if err := fl.Unlock(); err != nil {
		t.Fatalf("Unlock 1: %v", err)
	}
	if err := fl.LockExclusive(); err != nil {
		t.Fatalf("LockExclusive 2: %v", err)
	}
	if err := fl.Unlock(); err != nil {
		t.Fatalf("Unlock 2: %v", err)
	}
}
