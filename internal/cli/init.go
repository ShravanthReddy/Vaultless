// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Shravanth. All rights reserved.

package cli

import (
	"database/sql"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/vaultless/vaultless/internal/config"
	"github.com/vaultless/vaultless/internal/crypto"
	"github.com/vaultless/vaultless/internal/db"
	"github.com/vaultless/vaultless/internal/models"
	"github.com/vaultless/vaultless/internal/output"
)

func newInitCmd(gf *GlobalFlags) *cobra.Command {
	var name string
	var force bool

	cmd := &cobra.Command{
		Use:   "init",
		Short: "Initialize a new Vaultless project",
		Long:  `Create a .vaultless/ directory in the current project with encrypted database and configuration.`,
		Example: `  vaultless init
  vaultless init --name my-project
  vaultless init --force`,
		RunE: func(cmd *cobra.Command, args []string) error {
			securityInit()
			f := output.New(gf.JSON, gf.Quiet, gf.NoColor)

			cwd, err := os.Getwd()
			if err != nil {
				return err
			}

			vaultlessPath := filepath.Join(cwd, config.VaultlessDir)

			// Check if already initialized
			if _, err := os.Stat(vaultlessPath); err == nil && !force {
				return &models.ErrAlreadyExists{Entity: "project", Name: cwd}
			}

			// Prompt for project name
			if name == "" {
				name = filepath.Base(cwd)
				if !gf.Quiet {
					prompted, err := output.PromptString("Project name", name)
					if err == nil && prompted != "" {
						name = prompted
					}
				}
			}

			// Prompt for master password
			password, err := output.PromptPassword("Set master password (min 8 chars)")
			if err != nil {
				return fmt.Errorf("failed to read password: %w", err)
			}
			if err := models.ValidatePassword(password); err != nil {
				return err
			}

			// Confirm password
			confirm, err := output.PromptPassword("Confirm master password")
			if err != nil {
				return fmt.Errorf("failed to read password: %w", err)
			}
			if password != confirm {
				return &models.ErrValidation{Field: "password", Message: "passwords do not match"}
			}

			// Create directory structure
			if err := os.MkdirAll(vaultlessPath, 0700); err != nil {
				return err
			}

			projectID := crypto.GenerateUUID()
			now := time.Now().UTC()

			// Derive master key
			masterKey, salt, err := crypto.DeriveKey([]byte(password), nil, nil)
			if err != nil {
				return err
			}
			defer crypto.ZeroBytes(masterKey)

			// Create verification token
			verification, err := crypto.CreateVerificationToken(masterKey)
			if err != nil {
				return err
			}

			// Generate and store project key
			projectKey, err := crypto.GenerateProjectKey()
			if err != nil {
				return err
			}
			defer crypto.ZeroBytes(projectKey)

			if err := crypto.StoreProjectKey(projectID, projectKey, masterKey); err != nil {
				return err
			}

			// Create config
			pc := &models.ProjectConfig{
				Version: 1,
				Project: models.ProjectSection{
					Name:      name,
					ID:        projectID,
					CreatedAt: now.Format(time.RFC3339),
				},
				Environment: models.EnvironmentSection{Active: "dev"},
				Sync:        models.SyncSection{Backend: "none"},
				Secrets:     models.SecretsSection{MaxVersions: 50, MaxValueSize: 1 << 20},
				Audit:       models.AuditSection{Enabled: true, MaxEntries: 100000},
				Auth: models.AuthSection{
					Salt:         base64.StdEncoding.EncodeToString(salt),
					Verification: verification,
				},
			}
			if err := config.SaveProjectConfig(vaultlessPath, pc); err != nil {
				return err
			}

			// Initialize database with default environments
			dbPath := filepath.Join(vaultlessPath, "secrets.db")
			database, err := db.Open(dbPath)
			if err != nil {
				return err
			}
			defer database.Close()

			projects := db.NewProjectStore(database)
			envStore := db.NewEnvironmentStore(database)

			err = database.WithTx(newContext(), func(tx *sql.Tx) error {
				project := &models.Project{ID: projectID, Name: name}
				if err := projects.Create(newContext(), tx, project); err != nil {
					return err
				}

				defaultEnvs := []string{"dev", "staging", "prod"}
				for _, envName := range defaultEnvs {
					env := &models.Environment{
						ID:        crypto.GenerateUUID(),
						ProjectID: projectID,
						Name:      envName,
					}
					if err := envStore.Create(newContext(), tx, env); err != nil {
						return err
					}
				}
				return nil
			})
			if err != nil {
				return err
			}

			// Update .gitignore
			updateGitignore(cwd)

			// Cache session
			kc := crypto.NewKeychain()
			session := &crypto.SessionData{
				ProjectID: projectID,
				MasterKey: masterKey,
				CreatedAt: now,
				ExpiresAt: now.Add(24 * time.Hour),
			}
			_ = crypto.StoreSession(kc, projectID, session)

			f.Success("Initialized Vaultless project '%s'", name)
			f.Println("  Environments: dev, staging, prod")
			f.Println("  Active environment: dev")
			f.Printf("  Project path: %s\n", vaultlessPath)

			return nil
		},
	}

	cmd.Flags().StringVar(&name, "name", "", "Project name (default: directory name)")
	cmd.Flags().BoolVar(&force, "force", false, "Overwrite existing .vaultless/ directory")

	return cmd
}

func updateGitignore(projectDir string) {
	gitignorePath := filepath.Join(projectDir, ".gitignore")

	content, _ := os.ReadFile(gitignorePath)
	existing := string(content)

	entry := ".vaultless/secrets.db"
	if strings.Contains(existing, entry) {
		return
	}

	f, err := os.OpenFile(gitignorePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()

	if len(existing) > 0 && existing[len(existing)-1] != '\n' {
		f.WriteString("\n")
	}
	f.WriteString("\n# Vaultless encrypted database\n")
	f.WriteString(entry + "\n")
	f.WriteString(".vaultless/audit.log\n")
}

