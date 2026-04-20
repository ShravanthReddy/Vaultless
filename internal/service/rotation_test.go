// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Shravanth. All rights reserved.

package service

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/vaultless/vaultless/internal/crypto"
	"github.com/vaultless/vaultless/internal/db"
	"github.com/vaultless/vaultless/internal/models"
)

func testRotationSetup(t *testing.T) (*RotationService, *db.DB, string, []byte, context.Context) {
	t.Helper()
	tmpDir := t.TempDir()
	database, err := db.Open(filepath.Join(tmpDir, "test.db"))
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { database.Close() })

	ctx := context.Background()
	projectID := crypto.GenerateUUID()
	projectKey, _ := crypto.GenerateProjectKey()

	// Create project and environment
	now := time.Now().UTC().Format(time.RFC3339)
	envID := crypto.GenerateUUID()
	err = database.WithTx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx,
			"INSERT INTO projects (id, name, created_at, updated_at) VALUES (?, 'test', ?, ?)",
			projectID, now, now)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx,
			"INSERT INTO environments (id, project_id, name, created_at, updated_at) VALUES (?, ?, 'dev', ?, ?)",
			envID, projectID, now, now)
		return err
	})
	if err != nil {
		t.Fatalf("setup: %v", err)
	}

	// Add some secrets
	secretStore := db.NewSecretStore(database)
	versionStore := db.NewSecretVersionStore(database)
	for i, key := range []string{"API_KEY", "DB_HOST", "SECRET_TOKEN"} {
		plaintext := []byte("value-" + key)
		ciphertext, nonce, _ := crypto.Encrypt(projectKey, plaintext)
		secretID := crypto.GenerateUUID()

		err = database.WithTx(ctx, func(tx *sql.Tx) error {
			secret := &models.Secret{
				ID:             secretID,
				EnvironmentID:  envID,
				KeyName:        key,
				EncryptedValue: ciphertext,
				Nonce:          nonce,
				Version:        i + 1,
				CreatedBy:      "admin@example.com",
			}
			if err := secretStore.Upsert(ctx, tx, secret); err != nil {
				return err
			}
			ver := &models.SecretVersion{
				ID:             crypto.GenerateUUID(),
				SecretID:       secretID,
				Version:        i + 1,
				EncryptedValue: ciphertext,
				Nonce:          nonce,
				CreatedBy:      "admin@example.com",
				ChangeType:     "created",
			}
			return versionStore.Create(ctx, tx, ver)
		})
		if err != nil {
			t.Fatalf("setup secret: %v", err)
		}
	}

	svc := NewRotationService(database, projectID, projectKey, "admin@example.com")
	return svc, database, projectID, projectKey, ctx
}

func TestRotationService_Rotate(t *testing.T) {
	svc, database, projectID, oldKey, ctx := testRotationSetup(t)

	result, err := svc.Rotate(ctx)
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}

	if result.SecretsCount != 3 {
		t.Fatalf("expected 3 secrets rotated, got %d", result.SecretsCount)
	}
	if result.Event == nil {
		t.Fatal("expected rotation event")
	}
	if result.Event.Signature == "" {
		t.Fatal("expected signed event")
	}
	if result.InviteBundle == "" {
		t.Fatal("expected invite bundle")
	}
	if result.Passphrase == "" {
		t.Fatal("expected passphrase")
	}

	// Verify the new key can decrypt secrets
	newKey := result.NewKey(svc)
	envStore := db.NewEnvironmentStore(database)
	envs, _ := envStore.List(ctx, projectID)
	secretStore := db.NewSecretStore(database)

	for _, env := range envs {
		secrets, _ := secretStore.ListAll(ctx, env.ID)
		for _, sec := range secrets {
			plaintext, err := crypto.Decrypt(newKey, sec.EncryptedValue, sec.Nonce)
			if err != nil {
				t.Fatalf("failed to decrypt %q with new key: %v", sec.KeyName, err)
			}
			expected := "value-" + sec.KeyName
			if string(plaintext) != expected {
				t.Fatalf("expected %q, got %q", expected, string(plaintext))
			}
		}
	}

	// Old key should NOT decrypt secrets
	for _, env := range envs {
		secrets, _ := secretStore.ListAll(ctx, env.ID)
		for _, sec := range secrets {
			_, err := crypto.Decrypt(oldKey, sec.EncryptedValue, sec.Nonce)
			if err == nil {
				t.Fatalf("old key should not decrypt %q after rotation", sec.KeyName)
			}
		}
	}
}

func TestRotationService_Rotate_EventVerification(t *testing.T) {
	svc, _, _, _, ctx := testRotationSetup(t)

	result, err := svc.Rotate(ctx)
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}

	newKey := result.NewKey(svc)
	if !crypto.VerifyRotationEvent(result.Event, newKey) {
		t.Fatal("rotation event signature should be valid")
	}
}

func TestRotationService_Rotate_BundleRecovery(t *testing.T) {
	svc, _, _, _, ctx := testRotationSetup(t)

	result, err := svc.Rotate(ctx)
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}

	// Recover new key from bundle
	recoveredKey, err := crypto.DecryptInviteBundle(result.InviteBundle, result.Passphrase)
	if err != nil {
		t.Fatalf("DecryptInviteBundle: %v", err)
	}

	newKey := result.NewKey(svc)
	if len(recoveredKey) != len(newKey) {
		t.Fatal("recovered key size mismatch")
	}
	for i := range newKey {
		if newKey[i] != recoveredKey[i] {
			t.Fatal("recovered key does not match")
		}
	}
}

func TestRotationService_Rotate_EmptyProject(t *testing.T) {
	tmpDir := t.TempDir()
	database, _ := db.Open(filepath.Join(tmpDir, "test.db"))
	defer database.Close()

	ctx := context.Background()
	projectID := crypto.GenerateUUID()
	projectKey, _ := crypto.GenerateProjectKey()
	now := time.Now().UTC().Format(time.RFC3339)

	_ = database.WithTx(ctx, func(tx *sql.Tx) error {
		_, _ = tx.ExecContext(ctx,
			"INSERT INTO projects (id, name, created_at, updated_at) VALUES (?, 'empty', ?, ?)",
			projectID, now, now)
		return nil
	})

	svc := NewRotationService(database, projectID, projectKey, "admin@example.com")
	result, err := svc.Rotate(ctx)
	if err != nil {
		t.Fatalf("Rotate empty project: %v", err)
	}
	if result.SecretsCount != 0 {
		t.Fatalf("expected 0 secrets, got %d", result.SecretsCount)
	}
}
