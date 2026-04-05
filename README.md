# Vaultless

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)

A secure, local-first secrets manager for developers. No cloud accounts, no SaaS dependencies — your secrets stay on your machine, encrypted at rest, with team sharing via offline key exchange.

## Install

**macOS / Linux:**

```sh
curl -fsSL https://raw.githubusercontent.com/vaultless/vaultless/main/install.sh | sh
```

**Homebrew:**

```sh
brew install vaultless/tap/vaultless
```

**From source:**

```sh
go install github.com/vaultless/vaultless/cmd/vaultless@latest
```

## Quick Start

```sh
# Initialize a project
vaultless init

# Add secrets
vaultless set DATABASE_URL "postgres://..."
vaultless set API_KEY "sk-..."

# Use them
vaultless run -- node server.js

# Export to .env (when you need to)
vaultless export --format dotenv > .env
```

## Features

- **Offline-first** — no network required, no cloud accounts
- **Encrypted at rest** — AES-256-GCM with envelope encryption
- **Environment support** — development, staging, production
- **Team sharing** — offline key exchange via invite bundles
- **CI/CD tokens** — scoped, expirable read-only tokens
- **Audit log** — HMAC-signed NDJSON for tamper detection
- **Import/export** — .env files, JSON, YAML
- **Shell completion** — bash, zsh, fish, powershell

## Security Model

Vaultless uses a layered encryption architecture designed so that compromise of any single component does not expose secrets.

### Key Hierarchy

```
Master Password (user-memorized)
    │
    ▼
┌──────────────────────────┐
│ Argon2id Key Derivation  │  64 MB memory, 3 iterations, 4 threads
│ 16-byte random salt      │  → 256-bit Master Key
└──────────────────────────┘
    │
    ▼
┌──────────────────────────┐
│ Project Key (256-bit)    │  Encrypted with Master Key (AES-256-GCM)
│ Stored at                │  ~/.vaultless/keys/<project-id>.key
│ Format: salt ‖ nonce ‖   │  (76 bytes: 16 + 12 + 48)
│         ciphertext       │
└──────────────────────────┘
    │
    ▼
┌──────────────────────────┐
│ Secret Values            │  Each encrypted individually with Project Key
│ AES-256-GCM              │  Random 96-bit nonce per encryption
│ Stored in SQLite         │  encrypted_value + nonce columns
└──────────────────────────┘
```

### Algorithms

| Purpose | Algorithm | Parameters |
|---------|-----------|------------|
| Key derivation | Argon2id | 64 MB memory, 3 iterations, parallelism 4 |
| Secret encryption | AES-256-GCM | 96-bit random nonce, 128-bit auth tag |
| Audit log integrity | HMAC-SHA256 | Per-entry chained HMAC |
| Key exchange (team) | AES-256-GCM over passphrase-derived key | Via Argon2id |
| Key hierarchy derivation | HKDF-SHA256 | For deriving sub-keys |

### What's Encrypted Where

| Data | Storage | Encrypted? | Key |
|------|---------|-----------|-----|
| Secret values | `secrets.db` (SQLite) | Yes — AES-256-GCM | Project Key |
| Secret names (keys) | `secrets.db` | Plaintext | — |
| Project Key | `~/.vaultless/keys/*.key` | Yes — AES-256-GCM | Master Key |
| Master Key | OS keychain or memory | Session-only, never persisted to disk | — |
| Audit log | `.vaultless/audit.log` | No (HMAC-signed for tamper detection) | HMAC key |
| Team invite bundles | Transferred out-of-band | Yes — AES-256-GCM | Passphrase-derived |

### Threat Model

- **Disk theft**: Secrets are encrypted at rest. Attacker needs the master password to derive the master key.
- **Memory dump**: Master key is zeroed after use. Session keys are held in OS keychain with TTL.
- **Stolen database**: Without the project key file (`~/.vaultless/keys/`), the SQLite database is opaque.
- **Tampered audit log**: HMAC-SHA256 on each entry detects modification or deletion.
- **Team member compromise**: Each member has their own master password encrypting the shared project key. Revoking access requires key rotation.

### Design Decisions

- **No secret-name encryption**: Key names are stored in plaintext to enable efficient lookup and conflict detection. If secret names are sensitive, use opaque identifiers.
- **No network by default**: Sync is opt-in. The tool works fully offline.
- **Argon2id over bcrypt/scrypt**: Argon2id is the current OWASP recommendation for password hashing, with resistance to both GPU and side-channel attacks.

## Commands

```
vaultless init                      Initialize a new project
vaultless set KEY VALUE             Set a secret
vaultless get KEY                   Get a secret value
vaultless list                      List all secrets
vaultless delete KEY                Delete a secret
vaultless run -- COMMAND            Run a command with secrets injected
vaultless env list                  List environments
vaultless env create NAME           Create an environment
vaultless env switch NAME           Switch active environment
vaultless import FILE               Import secrets from .env/JSON/YAML
vaultless export                    Export secrets
vaultless team invite EMAIL         Generate a team invite bundle
vaultless team join BUNDLE          Join using an invite bundle
vaultless team list                 List team members
vaultless team remove EMAIL         Remove a team member
vaultless token create NAME         Create a CI/CD token
vaultless token list                List tokens
vaultless token revoke NAME         Revoke a token
vaultless audit                     View audit log
vaultless backup                    Backup the project
vaultless doctor                    Check project health
vaultless sync push/pull            Sync with remote backend
vaultless completion [shell]        Generate shell completions
```

## Configuration

Vaultless looks for `.vaultless/config.toml` in the project root:

```toml
[project]
name = "my-app"
default_environment = "development"

[security]
session_timeout = "8h"
```

## Documentation

- [ARCHITECTURE.md](ARCHITECTURE.md) — comprehensive technical guide
- [SECURITY.md](SECURITY.md) — security policy and responsible disclosure
- [CONTRIBUTING.md](CONTRIBUTING.md) — contribution guidelines

## License

[AGPL-3.0](LICENSE)
