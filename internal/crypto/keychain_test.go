// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Shravanth. All rights reserved.

package crypto

import (
	"encoding/json"
	"os"
	"testing"
	"time"
)

// mockKeychain implements Keychain for testing without OS keychain dependency.
type mockKeychain struct {
	store map[string][]byte
}

func newMockKeychain() *mockKeychain {
	return &mockKeychain{store: make(map[string][]byte)}
}

func (m *mockKeychain) Available() bool { return true }

func (m *mockKeychain) Store(service, account string, secret []byte) error {
	key := service + ":" + account
	m.store[key] = append([]byte{}, secret...)
	return nil
}

func (m *mockKeychain) Retrieve(service, account string) ([]byte, error) {
	key := service + ":" + account
	data, ok := m.store[key]
	if !ok {
		return nil, os.ErrNotExist
	}
	return data, nil
}

func (m *mockKeychain) Delete(service, account string) error {
	key := service + ":" + account
	delete(m.store, key)
	return nil
}

func TestStoreSession_LoadSession_Roundtrip(t *testing.T) {
	kc := newMockKeychain()
	projectID := "test-project"

	session := &SessionData{
		ProjectID: projectID,
		MasterKey: []byte("master-key-32-bytes-long-here!!!"),
		CreatedAt: time.Now().UTC(),
		ExpiresAt: time.Now().UTC().Add(1 * time.Hour),
	}

	if err := StoreSession(kc, projectID, session); err != nil {
		t.Fatalf("StoreSession: %v", err)
	}

	loaded, err := LoadSession(kc, projectID)
	if err != nil {
		t.Fatalf("LoadSession: %v", err)
	}

	if loaded.ProjectID != projectID {
		t.Fatalf("expected project ID %q, got %q", projectID, loaded.ProjectID)
	}
	if string(loaded.MasterKey) != string(session.MasterKey) {
		t.Fatal("master key mismatch")
	}
}

func TestLoadSession_Expired(t *testing.T) {
	kc := newMockKeychain()
	projectID := "expired-project"

	session := &SessionData{
		ProjectID: projectID,
		MasterKey: []byte("key"),
		CreatedAt: time.Now().UTC().Add(-2 * time.Hour),
		ExpiresAt: time.Now().UTC().Add(-1 * time.Hour), // Already expired
	}

	_ = StoreSession(kc, projectID, session)

	_, err := LoadSession(kc, projectID)
	if err == nil {
		t.Fatal("expected error for expired session")
	}
}

func TestLoadSession_NotFound(t *testing.T) {
	kc := newMockKeychain()

	_, err := LoadSession(kc, "nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent session")
	}
}

func TestDeleteSession(t *testing.T) {
	kc := newMockKeychain()
	projectID := "delete-me"

	session := &SessionData{
		ProjectID: projectID,
		MasterKey: []byte("key"),
		CreatedAt: time.Now().UTC(),
		ExpiresAt: time.Now().UTC().Add(time.Hour),
	}
	_ = StoreSession(kc, projectID, session)
	_ = DeleteSession(kc, projectID)

	_, err := LoadSession(kc, projectID)
	if err == nil {
		t.Fatal("expected error after delete")
	}
}

func TestSessionData_JSON(t *testing.T) {
	session := &SessionData{
		ProjectID: "proj-1",
		MasterKey: []byte{0x01, 0x02, 0x03},
		CreatedAt: time.Now().UTC(),
		ExpiresAt: time.Now().UTC().Add(time.Hour),
	}

	data, err := json.Marshal(session)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var loaded SessionData
	if err := json.Unmarshal(data, &loaded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if loaded.ProjectID != "proj-1" {
		t.Fatalf("expected 'proj-1', got %q", loaded.ProjectID)
	}
}

func TestFallbackKeychain_StoreRetrieveDelete(t *testing.T) {
	tmpDir := t.TempDir()
	os.Setenv("VAULTLESS_HOME", tmpDir)
	defer os.Unsetenv("VAULTLESS_HOME")

	kc := &fallbackKeychain{}
	if !kc.Available() {
		t.Fatal("fallback keychain should always be available")
	}

	secret := []byte("my-secret-data-for-keychain-test")
	if err := kc.Store("test-svc", "test-account", secret); err != nil {
		t.Fatalf("Store: %v", err)
	}

	retrieved, err := kc.Retrieve("test-svc", "test-account")
	if err != nil {
		t.Fatalf("Retrieve: %v", err)
	}
	if string(retrieved) != string(secret) {
		t.Fatalf("expected %q, got %q", secret, retrieved)
	}

	if err := kc.Delete("test-svc", "test-account"); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	_, err = kc.Retrieve("test-svc", "test-account")
	if err == nil {
		t.Fatal("expected error after delete")
	}
}

func TestFallbackKeychain_Retrieve_NotFound(t *testing.T) {
	tmpDir := t.TempDir()
	os.Setenv("VAULTLESS_HOME", tmpDir)
	defer os.Unsetenv("VAULTLESS_HOME")

	kc := &fallbackKeychain{}
	_, err := kc.Retrieve("nonexistent", "nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent entry")
	}
}
