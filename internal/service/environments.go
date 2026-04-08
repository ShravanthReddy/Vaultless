// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Shravanth. All rights reserved.

package service

import (
	"context"
	"database/sql"

	"github.com/vaultless/vaultless/internal/crypto"
	"github.com/vaultless/vaultless/internal/db"
	"github.com/vaultless/vaultless/internal/models"
)

// EnvironmentsService handles environment management.
type EnvironmentsService struct {
	database  *db.DB
	envs      *db.EnvironmentStore
	secrets   *db.SecretStore
	projectID string
}

func NewEnvironmentsService(database *db.DB, projectID string) *EnvironmentsService {
	return &EnvironmentsService{
		database:  database,
		envs:      db.NewEnvironmentStore(database),
		secrets:   db.NewSecretStore(database),
		projectID: projectID,
	}
}

func (s *EnvironmentsService) Create(ctx context.Context, name string) error {
	if err := models.ValidateEnvName(name); err != nil {
		return err
	}

	existing, err := s.envs.GetByName(ctx, s.projectID, name)
	if err != nil {
		return err
	}
	if existing != nil {
		return &models.ErrAlreadyExists{Entity: "environment", Name: name}
	}

	return s.database.WithTx(ctx, func(tx *sql.Tx) error {
		env := &models.Environment{
			ID:        crypto.GenerateUUID(),
			ProjectID: s.projectID,
			Name:      name,
		}
		return s.envs.Create(ctx, tx, env)
	})
}

func (s *EnvironmentsService) Delete(ctx context.Context, name string) error {
	env, err := s.envs.GetByName(ctx, s.projectID, name)
	if err != nil {
		return err
	}
	if env == nil {
		return &models.ErrNotFound{Entity: "environment", Name: name}
	}

	return s.database.WithTx(ctx, func(tx *sql.Tx) error {
		return s.envs.Delete(ctx, tx, env.ID)
	})
}

func (s *EnvironmentsService) List(ctx context.Context) ([]models.Environment, error) {
	return s.envs.List(ctx, s.projectID)
}

func (s *EnvironmentsService) Diff(ctx context.Context, env1Name, env2Name string) (*EnvDiff, error) {
	env1, err := s.envs.GetByName(ctx, s.projectID, env1Name)
	if err != nil {
		return nil, err
	}
	if env1 == nil {
		return nil, &models.ErrNotFound{Entity: "environment", Name: env1Name}
	}

	env2, err := s.envs.GetByName(ctx, s.projectID, env2Name)
	if err != nil {
		return nil, err
	}
	if env2 == nil {
		return nil, &models.ErrNotFound{Entity: "environment", Name: env2Name}
	}

	keys1, err := s.secrets.ListKeys(ctx, env1.ID)
	if err != nil {
		return nil, err
	}
	keys2, err := s.secrets.ListKeys(ctx, env2.ID)
	if err != nil {
		return nil, err
	}

	set1 := make(map[string]bool, len(keys1))
	for _, k := range keys1 {
		set1[k] = true
	}
	set2 := make(map[string]bool, len(keys2))
	for _, k := range keys2 {
		set2[k] = true
	}

	diff := &EnvDiff{
		Env1Name: env1Name,
		Env2Name: env2Name,
	}
	for _, k := range keys1 {
		if !set2[k] {
			diff.OnlyInEnv1 = append(diff.OnlyInEnv1, k)
		} else {
			diff.InBoth = append(diff.InBoth, k)
		}
	}
	for _, k := range keys2 {
		if !set1[k] {
			diff.OnlyInEnv2 = append(diff.OnlyInEnv2, k)
		}
	}

	return diff, nil
}

func (s *EnvironmentsService) Clone(ctx context.Context, srcName, dstName string) error {
	if err := models.ValidateEnvName(dstName); err != nil {
		return err
	}

	src, err := s.envs.GetByName(ctx, s.projectID, srcName)
	if err != nil {
		return err
	}
	if src == nil {
		return &models.ErrNotFound{Entity: "environment", Name: srcName}
	}

	existing, err := s.envs.GetByName(ctx, s.projectID, dstName)
	if err != nil {
		return err
	}
	if existing != nil {
		return &models.ErrAlreadyExists{Entity: "environment", Name: dstName}
	}

	return s.database.WithTx(ctx, func(tx *sql.Tx) error {
		dst := &models.Environment{
			ID:        crypto.GenerateUUID(),
			ProjectID: s.projectID,
			Name:      dstName,
		}
		if err := s.envs.Create(ctx, tx, dst); err != nil {
			return err
		}
		return s.secrets.CopyAll(ctx, tx, src.ID, dst.ID, crypto.GenerateUUID)
	})
}

// EnvDiff represents the difference between two environments.
type EnvDiff struct {
	Env1Name   string
	Env2Name   string
	OnlyInEnv1 []string
	OnlyInEnv2 []string
	InBoth     []string
}
