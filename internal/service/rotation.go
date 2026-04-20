// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Shravanth. All rights reserved.

package service

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/vaultless/vaultless/internal/crypto"
	"github.com/vaultless/vaultless/internal/db"
	"github.com/vaultless/vaultless/internal/models"
)

// RotationResult contains the outcome of a key rotation.
type RotationResult struct {
	Event         *crypto.RotationEvent
	SecretsCount  int
	InviteBundle  string
	Passphrase    string
}

// RotationService handles the full key rotation workflow.
type RotationService struct {
	database   *db.DB
	secrets    *db.SecretStore
	versions   *db.SecretVersionStore
	envs       *db.EnvironmentStore
	projectID  string
	projectKey []byte
	identity   string
}

func NewRotationService(database *db.DB, projectID string, projectKey []byte, identity string) *RotationService {
	return &RotationService{
		database:   database,
		secrets:    db.NewSecretStore(database),
		versions:   db.NewSecretVersionStore(database),
		envs:       db.NewEnvironmentStore(database),
		projectID:  projectID,
		projectKey: projectKey,
		identity:   identity,
	}
}

// Rotate performs a full key rotation:
// 1. Generates a new project key
// 2. Re-encrypts all secrets with the new key
// 3. Creates a signed rotation event
// 4. Generates an invite bundle for distribution
func (s *RotationService) Rotate(ctx context.Context) (*RotationResult, error) {
	// Gather all secrets across all environments
	envs, err := s.envs.List(ctx, s.projectID)
	if err != nil {
		return nil, fmt.Errorf("failed to list environments: %w", err)
	}

	type secretRef struct {
		envID  string
		secret models.Secret
	}
	var allSecrets []secretRef

	for _, env := range envs {
		secrets, err := s.secrets.ListAll(ctx, env.ID)
		if err != nil {
			return nil, fmt.Errorf("failed to list secrets for env %q: %w", env.Name, err)
		}
		for _, sec := range secrets {
			allSecrets = append(allSecrets, secretRef{envID: env.ID, secret: sec})
		}
	}

	// Generate new key and rotation event
	newKey, event, err := crypto.RotateProjectKey(s.projectKey, s.identity, len(allSecrets))
	if err != nil {
		return nil, err
	}

	// Re-encrypt all secrets in a single transaction
	err = s.database.WithTx(ctx, func(tx *sql.Tx) error {
		for _, ref := range allSecrets {
			newCiphertext, newNonce, err := crypto.ReEncryptSecret(
				s.projectKey, newKey,
				ref.secret.EncryptedValue, ref.secret.Nonce,
			)
			if err != nil {
				return fmt.Errorf("failed to re-encrypt secret %q: %w", ref.secret.KeyName, err)
			}

			ref.secret.EncryptedValue = newCiphertext
			ref.secret.Nonce = newNonce
			if err := s.secrets.Upsert(ctx, tx, &ref.secret); err != nil {
				return fmt.Errorf("failed to update secret %q: %w", ref.secret.KeyName, err)
			}

			// Also re-encrypt all versions
			versions, err := s.versions.ListBySecretID(ctx, ref.secret.ID)
			if err != nil {
				return fmt.Errorf("failed to list versions for %q: %w", ref.secret.KeyName, err)
			}
			for _, ver := range versions {
				newVerCipher, newVerNonce, err := crypto.ReEncryptSecret(
					s.projectKey, newKey,
					ver.EncryptedValue, ver.Nonce,
				)
				if err != nil {
					return fmt.Errorf("failed to re-encrypt version %d of %q: %w", ver.Version, ref.secret.KeyName, err)
				}
				ver.EncryptedValue = newVerCipher
				ver.Nonce = newVerNonce
				// Update version in-place via delete+create
				if err := s.updateVersion(ctx, tx, &ver); err != nil {
					return fmt.Errorf("failed to update version: %w", err)
				}
			}
		}
		return nil
	})
	if err != nil {
		crypto.ZeroBytes(newKey)
		return nil, err
	}

	// Generate invite bundle for distributing the new key
	passphraseBytes, err := crypto.GenerateRandomBytes(16)
	if err != nil {
		crypto.ZeroBytes(newKey)
		return nil, fmt.Errorf("failed to generate passphrase: %w", err)
	}
	passphrase := fmt.Sprintf("%x", passphraseBytes)

	bundle, err := crypto.CreateRotationBundle(newKey, passphrase)
	if err != nil {
		crypto.ZeroBytes(newKey)
		return nil, fmt.Errorf("failed to create rotation bundle: %w", err)
	}

	// Store the new key on disk
	// The caller should provide the master key for storage; for now, update in-memory
	s.projectKey = newKey

	return &RotationResult{
		Event:        event,
		SecretsCount: len(allSecrets),
		InviteBundle: bundle,
		Passphrase:   passphrase,
	}, nil
}

// updateVersion updates a secret version's encrypted value in-place.
func (s *RotationService) updateVersion(ctx context.Context, tx *sql.Tx, ver *models.SecretVersion) error {
	_, err := tx.ExecContext(ctx,
		`UPDATE secret_versions SET encrypted_value = ?, nonce = ? WHERE id = ?`,
		ver.EncryptedValue, ver.Nonce, ver.ID,
	)
	return err
}

// NewKey returns the new project key after rotation.
// The caller must store this key securely.
func (r *RotationResult) NewKey(svc *RotationService) []byte {
	return svc.projectKey
}
