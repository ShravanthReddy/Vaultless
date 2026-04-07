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

// SecretsService handles secret management (encrypt + store + version).
type SecretsService struct {
	database    *db.DB
	secrets     *db.SecretStore
	versions    *db.SecretVersionStore
	envs        *db.EnvironmentStore
	projectID   string
	projectKey  []byte
	maxVersions int
	identity    string
}

func NewSecretsService(database *db.DB, projectID string, projectKey []byte, maxVersions int, identity string) *SecretsService {
	return &SecretsService{
		database:    database,
		secrets:     db.NewSecretStore(database),
		versions:    db.NewSecretVersionStore(database),
		envs:        db.NewEnvironmentStore(database),
		projectID:   projectID,
		projectKey:  projectKey,
		maxVersions: maxVersions,
		identity:    identity,
	}
}

func (s *SecretsService) Set(ctx context.Context, envName, keyName string, value []byte, force bool) (version int, err error) {
	if err := models.ValidateKeyName(keyName); err != nil {
		return 0, err
	}
	if err := models.ValidateSecretValue(value); err != nil {
		return 0, err
	}

	env, err := s.resolveEnv(ctx, envName)
	if err != nil {
		return 0, err
	}

	ciphertext, nonce, err := crypto.Encrypt(s.projectKey, value)
	if err != nil {
		return 0, fmt.Errorf("failed to encrypt secret: %w", err)
	}
	crypto.ZeroBytes(value)

	var resultVersion int
	err = s.database.WithTx(ctx, func(tx *sql.Tx) error {
		existing, err := s.secrets.GetByKey(ctx, env.ID, keyName)
		if err != nil {
			return err
		}

		if existing != nil && !existing.IsDeleted && !force {
			return &models.ErrAlreadyExists{Entity: "secret", Name: keyName}
		}

		if existing != nil && !existing.IsDeleted {
			resultVersion = existing.Version + 1
			existing.EncryptedValue = ciphertext
			existing.Nonce = nonce
			existing.Version = resultVersion
			existing.CreatedBy = s.identity
			existing.IsDeleted = false
			if err := s.secrets.Upsert(ctx, tx, existing); err != nil {
				return err
			}

			ver := &models.SecretVersion{
				ID:             crypto.GenerateUUID(),
				SecretID:       existing.ID,
				Version:        resultVersion,
				EncryptedValue: ciphertext,
				Nonce:          nonce,
				CreatedBy:      s.identity,
				ChangeType:     "updated",
			}
			if err := s.versions.Create(ctx, tx, ver); err != nil {
				return err
			}

			return s.versions.PruneOldVersions(ctx, tx, existing.ID, s.maxVersions)
		}

		resultVersion = 1
		secretID := crypto.GenerateUUID()
		changeType := "created"
		if existing != nil && existing.IsDeleted {
			secretID = existing.ID
			changeType = "restored"
			// Find the max version from history to avoid conflicts
			versions, verErr := s.versions.ListBySecretID(ctx, existing.ID)
			if verErr == nil && len(versions) > 0 {
				resultVersion = versions[0].Version + 1 // ListBySecretID returns DESC order
			} else {
				resultVersion = existing.Version + 1
			}
		}
		secret := &models.Secret{
			ID:             secretID,
			EnvironmentID:  env.ID,
			KeyName:        keyName,
			EncryptedValue: ciphertext,
			Nonce:          nonce,
			Version:        resultVersion,
			CreatedBy:      s.identity,
		}
		if err := s.secrets.Upsert(ctx, tx, secret); err != nil {
			return err
		}

		ver := &models.SecretVersion{
			ID:             crypto.GenerateUUID(),
			SecretID:       secretID,
			Version:        resultVersion,
			EncryptedValue: ciphertext,
			Nonce:          nonce,
			CreatedBy:      s.identity,
			ChangeType:     changeType,
		}
		return s.versions.Create(ctx, tx, ver)
	})

	return resultVersion, err
}

func (s *SecretsService) Get(ctx context.Context, envName, keyName string) (*models.SecretWithValue, error) {
	env, err := s.resolveEnv(ctx, envName)
	if err != nil {
		return nil, err
	}

	secret, err := s.secrets.GetByKey(ctx, env.ID, keyName)
	if err != nil {
		return nil, err
	}
	if secret == nil || secret.IsDeleted {
		return nil, &models.ErrNotFound{Entity: "secret", Name: keyName, Env: envName}
	}

	plaintext, err := crypto.Decrypt(s.projectKey, secret.EncryptedValue, secret.Nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt secret '%s': %w", keyName, err)
	}

	return &models.SecretWithValue{
		Secret: *secret,
		Value:  plaintext,
	}, nil
}

func (s *SecretsService) GetVersion(ctx context.Context, envName, keyName string, version int) (*models.SecretWithValue, error) {
	env, err := s.resolveEnv(ctx, envName)
	if err != nil {
		return nil, err
	}

	secret, err := s.secrets.GetByKey(ctx, env.ID, keyName)
	if err != nil {
		return nil, err
	}
	if secret == nil {
		return nil, &models.ErrNotFound{Entity: "secret", Name: keyName, Env: envName}
	}

	ver, err := s.versions.GetByVersion(ctx, secret.ID, version)
	if err != nil {
		return nil, err
	}
	if ver == nil {
		return nil, &models.ErrNotFound{Entity: "secret version", Name: fmt.Sprintf("%s@v%d", keyName, version)}
	}

	plaintext, err := crypto.Decrypt(s.projectKey, ver.EncryptedValue, ver.Nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt secret version: %w", err)
	}

	return &models.SecretWithValue{
		Secret: *secret,
		Value:  plaintext,
	}, nil
}

func (s *SecretsService) Delete(ctx context.Context, envName, keyName string, purge bool) error {
	env, err := s.resolveEnv(ctx, envName)
	if err != nil {
		return err
	}

	secret, err := s.secrets.GetByKey(ctx, env.ID, keyName)
	if err != nil {
		return err
	}
	if secret == nil || (secret.IsDeleted && !purge) {
		return &models.ErrNotFound{Entity: "secret", Name: keyName, Env: envName}
	}

	return s.database.WithTx(ctx, func(tx *sql.Tx) error {
		if purge {
			return s.secrets.Purge(ctx, tx, env.ID, keyName)
		}

		if err := s.secrets.SoftDelete(ctx, tx, env.ID, keyName); err != nil {
			return err
		}

		ver := &models.SecretVersion{
			ID:             crypto.GenerateUUID(),
			SecretID:       secret.ID,
			Version:        secret.Version + 1,
			EncryptedValue: secret.EncryptedValue,
			Nonce:          secret.Nonce,
			CreatedBy:      s.identity,
			ChangeType:     "deleted",
		}
		return s.versions.Create(ctx, tx, ver)
	})
}

func (s *SecretsService) DeleteAllEnvs(ctx context.Context, keyName string) error {
	envs, err := s.envs.List(ctx, s.projectID)
	if err != nil {
		return err
	}
	for _, env := range envs {
		secret, err := s.secrets.GetByKey(ctx, env.ID, keyName)
		if err != nil {
			return err
		}
		if secret != nil && !secret.IsDeleted {
			if err := s.Delete(ctx, env.Name, keyName, false); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *SecretsService) List(ctx context.Context, envName string) ([]models.SecretListEntry, error) {
	env, err := s.resolveEnv(ctx, envName)
	if err != nil {
		return nil, err
	}
	return s.secrets.List(ctx, env.ID)
}

func (s *SecretsService) ListAllEnvs(ctx context.Context) (map[string][]models.SecretListEntry, error) {
	envs, err := s.envs.List(ctx, s.projectID)
	if err != nil {
		return nil, err
	}

	result := make(map[string][]models.SecretListEntry)
	for _, env := range envs {
		entries, err := s.secrets.List(ctx, env.ID)
		if err != nil {
			return nil, err
		}
		result[env.Name] = entries
	}
	return result, nil
}

func (s *SecretsService) ListDecrypted(ctx context.Context, envName string) (map[string][]byte, error) {
	env, err := s.resolveEnv(ctx, envName)
	if err != nil {
		return nil, err
	}

	secrets, err := s.secrets.ListAll(ctx, env.ID)
	if err != nil {
		return nil, err
	}

	result := make(map[string][]byte, len(secrets))
	for _, sec := range secrets {
		plaintext, err := crypto.Decrypt(s.projectKey, sec.EncryptedValue, sec.Nonce)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt secret '%s': %w", sec.KeyName, err)
		}
		result[sec.KeyName] = plaintext
	}
	return result, nil
}

func (s *SecretsService) ListKeys(ctx context.Context, envName string) ([]string, error) {
	env, err := s.resolveEnv(ctx, envName)
	if err != nil {
		return nil, err
	}
	return s.secrets.ListKeys(ctx, env.ID)
}

func (s *SecretsService) History(ctx context.Context, envName, keyName string) ([]models.SecretVersion, error) {
	env, err := s.resolveEnv(ctx, envName)
	if err != nil {
		return nil, err
	}

	secret, err := s.secrets.GetByKey(ctx, env.ID, keyName)
	if err != nil {
		return nil, err
	}
	if secret == nil {
		return nil, &models.ErrNotFound{Entity: "secret", Name: keyName, Env: envName}
	}

	return s.versions.ListBySecretID(ctx, secret.ID)
}

func (s *SecretsService) Rollback(ctx context.Context, envName, keyName string, version int) error {
	env, err := s.resolveEnv(ctx, envName)
	if err != nil {
		return err
	}

	secret, err := s.secrets.GetByKey(ctx, env.ID, keyName)
	if err != nil {
		return err
	}
	if secret == nil {
		return &models.ErrNotFound{Entity: "secret", Name: keyName, Env: envName}
	}

	ver, err := s.versions.GetByVersion(ctx, secret.ID, version)
	if err != nil {
		return err
	}
	if ver == nil {
		return &models.ErrNotFound{Entity: "secret version", Name: fmt.Sprintf("%s@v%d", keyName, version)}
	}

	return s.database.WithTx(ctx, func(tx *sql.Tx) error {
		newVersion := secret.Version + 1
		secret.EncryptedValue = ver.EncryptedValue
		secret.Nonce = ver.Nonce
		secret.Version = newVersion
		secret.CreatedBy = s.identity
		secret.IsDeleted = false
		if err := s.secrets.Upsert(ctx, tx, secret); err != nil {
			return err
		}

		newVer := &models.SecretVersion{
			ID:             crypto.GenerateUUID(),
			SecretID:       secret.ID,
			Version:        newVersion,
			EncryptedValue: ver.EncryptedValue,
			Nonce:          ver.Nonce,
			CreatedBy:      s.identity,
			ChangeType:     "restored",
		}
		return s.versions.Create(ctx, tx, newVer)
	})
}

func (s *SecretsService) resolveEnv(ctx context.Context, envName string) (*models.Environment, error) {
	env, err := s.envs.GetByName(ctx, s.projectID, envName)
	if err != nil {
		return nil, err
	}
	if env == nil {
		return nil, &models.ErrNotFound{Entity: "environment", Name: envName}
	}
	return env, nil
}
