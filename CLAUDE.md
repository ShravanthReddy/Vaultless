# AI Assistance for Vaultless

This file provides context for AI assistants helping with Vaultless development.

## Project Overview

Vaultless is an offline-first, zero-dependency secrets management CLI written in Go.
It uses AES-256-GCM encryption with Argon2id key derivation, storing secrets in SQLite.

## Architecture

- `cmd/vaultless/` - Entry point
- `internal/cli/` - Cobra commands (36 commands)
- `internal/service/` - Business logic
- `internal/db/` - SQLite storage
- `internal/crypto/` - Encryption (AES-GCM, Argon2id, HMAC)
- `internal/config/` - Configuration management
- `internal/sync/` - Git/filesystem sync

## Key Technologies

- Go 1.22+
- modernc.org/sqlite (pure Go SQLite)
- golang.org/x/crypto/argon2
- github.com/spf13/cobra

## Development

```bash
# Build
go build ./cmd/vaultless

# Test
go test ./...

# Run locally
go run ./cmd/vaultless init
```

## License

AGPL-3.0
