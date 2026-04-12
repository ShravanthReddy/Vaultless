// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Shravanth. All rights reserved.

package cli

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"github.com/vaultless/vaultless/internal/config"
	"github.com/vaultless/vaultless/internal/crypto"
	"github.com/vaultless/vaultless/internal/db"
	"github.com/vaultless/vaultless/internal/models"
	"github.com/vaultless/vaultless/internal/output"
	"github.com/vaultless/vaultless/internal/service"
	syncpkg "github.com/vaultless/vaultless/internal/sync"
)

// GlobalFlags holds CLI-wide flags.
type GlobalFlags struct {
	Env     string
	JSON    bool
	Quiet   bool
	Force   bool
	NoColor bool
	Verbose bool
}

// appContext holds initialized application state for commands.
type appContext struct {
	cfg        *config.ResolvedConfig
	database   *db.DB
	projectKey []byte
	formatter  *output.Formatter
	audit      *service.AuditWriter
	identity   string
}

func NewRootCommand(version, commit, date string) *cobra.Command {
	var flags GlobalFlags

	root := &cobra.Command{
		Use:   "vaultless",
		Short: "Zero-dependency secrets management for developers",
		Long: `Vaultless is an offline-first secrets management tool that replaces .env files
with encrypted, versioned, and syncable secrets — all in a single binary.`,
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	pf := root.PersistentFlags()
	pf.StringVarP(&flags.Env, "env", "e", "", "Override active environment")
	pf.BoolVarP(&flags.JSON, "json", "j", false, "Output in JSON format")
	pf.BoolVarP(&flags.Quiet, "quiet", "q", false, "Suppress non-essential output")
	pf.BoolVarP(&flags.Force, "force", "f", false, "Skip confirmation prompts")
	pf.BoolVar(&flags.NoColor, "no-color", false, "Disable colored output")
	pf.BoolVarP(&flags.Verbose, "verbose", "v", false, "Enable verbose/debug output")

	root.AddCommand(
		newInitCmd(&flags),
		newSetCmd(&flags),
		newGetCmd(&flags),
		newDeleteCmd(&flags),
		newListCmd(&flags),
		newHistoryCmd(&flags),
		newRollbackCmd(&flags),
		newRunCmd(&flags),
		newImportCmd(&flags),
		newExportCmd(&flags),
		newEnvCmd(&flags),
		newPushCmd(&flags),
		newPullCmd(&flags),
		newStatusCmd(&flags),
		newTeamCmd(&flags),
		newTokenCmd(&flags),
		newAuditCmd(&flags),
		newConfigCmd(&flags),
		newBackupCmd(&flags),
		newRestoreCmd(&flags),
		newDoctorCmd(&flags),
		newCompletionCmd(&flags),
		newVersionCmd(version, commit, date),
	)

	return root
}

// initAppContext initializes the application context needed by most commands.
func initAppContext(flags *GlobalFlags) (*appContext, error) {
	securityInit()

	gf := &config.GlobalFlags{
		Env:     flags.Env,
		JSON:    flags.JSON,
		Quiet:   flags.Quiet,
		Force:   flags.Force,
		NoColor: flags.NoColor,
		Verbose: flags.Verbose,
	}

	cfg, err := config.Load(gf)
	if err != nil {
		return nil, err
	}

	if cfg.ProjectPath == "" {
		return nil, &models.ErrNotFound{
			Entity: "project",
			Name:   "Not a vaultless project (or any parent up to root). Run 'vaultless init' to create one.",
		}
	}

	dbPath := filepath.Join(cfg.ProjectPath, "secrets.db")
	database, err := db.Open(dbPath)
	if err != nil {
		return nil, err
	}

	f := output.New(cfg.OutputJSON, cfg.Quiet, cfg.NoColor)

	// Resolve project key
	projectKey, err := resolveProjectKey(cfg)
	if err != nil {
		database.Close()
		return nil, err
	}

	identity := cfg.UserName
	if identity == "" {
		identity = cfg.UserEmail
	}
	if identity == "" {
		identity = "unknown"
	}

	auditPath := filepath.Join(cfg.ProjectPath, "audit.log")
	audit := service.NewAuditWriter(auditPath, projectKey)

	return &appContext{
		cfg:        cfg,
		database:   database,
		projectKey: projectKey,
		formatter:  f,
		audit:      audit,
		identity:   identity,
	}, nil
}

func (ac *appContext) close() {
	if ac.database != nil {
		ac.database.Close()
	}
	if ac.projectKey != nil {
		crypto.ZeroBytes(ac.projectKey)
	}
}

func resolveProjectKey(cfg *config.ResolvedConfig) ([]byte, error) {
	// Try token auth first
	if cfg.Token != "" {
		// Token auth — project key should already be available
		return crypto.LoadProjectKey(cfg.ProjectID, getOrPromptMasterKey(cfg))
	}

	// Try cached session
	kc := crypto.NewKeychain()
	session, err := crypto.LoadSession(kc, cfg.ProjectID)
	if err == nil && session != nil {
		return crypto.LoadProjectKey(cfg.ProjectID, session.MasterKey)
	}

	// Prompt for password
	return getProjectKeyInteractive(cfg, kc)
}

func getProjectKeyInteractive(cfg *config.ResolvedConfig, kc crypto.Keychain) ([]byte, error) {
	password, err := output.PromptPassword("Master password")
	if err != nil {
		return nil, fmt.Errorf("failed to read password: %w", err)
	}

	if len(password) < models.MinPasswordLen {
		return nil, &models.ErrValidation{Field: "password", Message: fmt.Sprintf("must be at least %d characters", models.MinPasswordLen)}
	}

	// Derive master key
	salt, err := base64.StdEncoding.DecodeString(cfg.AuthConf.Salt)
	if err != nil {
		return nil, fmt.Errorf("invalid salt in config: %w", err)
	}

	masterKey, _, err := crypto.DeriveKey([]byte(password), salt, nil)
	if err != nil {
		return nil, err
	}

	// Verify master key
	if cfg.AuthConf.Verification != "" && !crypto.VerifyMasterKey(masterKey, cfg.AuthConf.Verification) {
		crypto.ZeroBytes(masterKey)
		return nil, &models.ErrAuth{Msg: "incorrect master password"}
	}

	// Cache session
	now := time.Now().UTC()
	sessionData := &crypto.SessionData{
		ProjectID: cfg.ProjectID,
		MasterKey: masterKey,
		CreatedAt: now,
		ExpiresAt: now.Add(cfg.SessionTTL),
	}
	_ = crypto.StoreSession(kc, cfg.ProjectID, sessionData)

	projectKey, err := crypto.LoadProjectKey(cfg.ProjectID, masterKey)
	if err != nil {
		crypto.ZeroBytes(masterKey)
		return nil, err
	}

	return projectKey, nil
}

func getOrPromptMasterKey(cfg *config.ResolvedConfig) []byte {
	password, err := output.PromptPassword("Master password")
	if err != nil {
		return nil
	}
	salt, err := base64.StdEncoding.DecodeString(cfg.AuthConf.Salt)
	if err != nil {
		return nil
	}
	key, _, _ := crypto.DeriveKey([]byte(password), salt, nil)
	return key
}

func securityInit() {
	// Disable core dumps
	var rlimit syscall.Rlimit
	_ = syscall.Setrlimit(syscall.RLIMIT_CORE, &rlimit)

	// Set strict umask
	syscall.Umask(0077)
}

func exitCode(err error) int {
	if err == nil {
		return 0
	}

	var notFound *models.ErrNotFound
	var validation *models.ErrValidation
	var auth *models.ErrAuth
	var perm *models.ErrPermission
	var conflict *models.ErrConflict
	var exists *models.ErrAlreadyExists
	var dbErr *models.ErrDatabase

	switch {
	case errors.As(err, &notFound), errors.As(err, &validation):
		return 1
	case errors.As(err, &auth):
		return 3
	case errors.As(err, &perm):
		return 4
	case errors.As(err, &conflict), errors.As(err, &exists):
		return 5
	case errors.As(err, &dbErr):
		return 6
	default:
		return 1
	}
}

func newContext() context.Context {
	return context.Background()
}

// newSyncBackend creates the appropriate sync backend from config.
func newSyncBackend(cfg *config.ResolvedConfig) syncpkg.SyncBackend {
	switch cfg.SyncBackend {
	case "git":
		return syncpkg.NewGitBackend(cfg.SyncRemote, cfg.ProjectID, cfg.SyncBranch)
	case "filesystem":
		return syncpkg.NewFilesystemBackend(cfg.SyncRemote, cfg.ProjectID)
	default:
		return nil
	}
}

// handleError prints the error and exits with the appropriate code.
func handleError(f *output.Formatter, err error) {
	if err != nil {
		f.Error("%s", err.Error())
		os.Exit(exitCode(err))
	}
}
