// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Shravanth. All rights reserved.

package service

import (
	"context"
	"os"
	"path/filepath"

	"github.com/vaultless/vaultless/internal/crypto"
	"github.com/vaultless/vaultless/internal/db"
	"github.com/vaultless/vaultless/internal/models"
)

// DoctorService runs health checks on the project.
type DoctorService struct {
	database    *db.DB
	projectPath string
	projectID   string
	projectKey  []byte
}

func NewDoctorService(database *db.DB, projectPath, projectID string, projectKey []byte) *DoctorService {
	return &DoctorService{
		database:    database,
		projectPath: projectPath,
		projectID:   projectID,
		projectKey:  projectKey,
	}
}

// RunAll runs all health checks and returns results.
func (s *DoctorService) RunAll(ctx context.Context) []models.DoctorCheck {
	var checks []models.DoctorCheck

	// Database integrity
	checks = append(checks, s.checkDatabaseIntegrity(ctx))

	// Config file
	checks = append(checks, s.checkConfigFile())

	// Project key
	checks = append(checks, s.checkProjectKey())

	// Database connectivity
	checks = append(checks, s.checkDatabaseConnectivity(ctx))

	return checks
}

func (s *DoctorService) checkDatabaseIntegrity(ctx context.Context) models.DoctorCheck {
	result, err := s.database.IntegrityCheck(ctx)
	if err != nil {
		return models.DoctorCheck{Name: "database-integrity", Status: "fail", Message: err.Error()}
	}
	if result != "ok" {
		return models.DoctorCheck{Name: "database-integrity", Status: "fail", Message: "integrity check returned: " + result}
	}
	return models.DoctorCheck{Name: "database-integrity", Status: "pass", Message: "Database integrity OK"}
}

func (s *DoctorService) checkConfigFile() models.DoctorCheck {
	configPath := filepath.Join(s.projectPath, "config.toml")
	if _, err := os.Stat(configPath); err != nil {
		return models.DoctorCheck{Name: "config-file", Status: "fail", Message: "config.toml not found"}
	}
	return models.DoctorCheck{Name: "config-file", Status: "pass", Message: "Config file exists"}
}

func (s *DoctorService) checkProjectKey() models.DoctorCheck {
	if !crypto.ProjectKeyExists(s.projectID) {
		return models.DoctorCheck{Name: "project-key", Status: "fail", Message: "Project key file not found"}
	}
	return models.DoctorCheck{Name: "project-key", Status: "pass", Message: "Project key accessible"}
}

func (s *DoctorService) checkDatabaseConnectivity(ctx context.Context) models.DoctorCheck {
	var result int
	err := s.database.Conn().QueryRowContext(ctx, "SELECT 1").Scan(&result)
	if err != nil {
		return models.DoctorCheck{Name: "database-connectivity", Status: "fail", Message: err.Error()}
	}
	return models.DoctorCheck{Name: "database-connectivity", Status: "pass", Message: "Database responsive"}
}
