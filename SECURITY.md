# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in Vaultless, **please do not open a public issue.**

Instead, report it privately:

- **GitHub:** Open a [private security advisory](https://github.com/vaultless/vaultless/security/advisories/new)
- **Email:** shrvnthrdy@gmail.com (subject: `[SECURITY] <brief description>`)

Include as much detail as possible:

1. Description of the vulnerability
2. Steps to reproduce
3. Affected versions
4. Potential impact
5. Suggested fix (if any)

## Response Timeline

| Step | Target |
|------|--------|
| Acknowledgment | Within 48 hours |
| Triage and severity assessment | Within 5 business days |
| Patch for CRITICAL/HIGH issues | Within 14 days |
| Public disclosure (coordinated) | After patch is released |

## Scope

The following are in scope for security reports:

- Encryption/decryption flaws (AES-256-GCM, Argon2id, HMAC)
- Key material leaks (memory, disk, logs)
- Authentication or authorization bypasses
- Path traversal or file permission issues
- Dependency vulnerabilities with exploitable impact

Out of scope:

- Denial-of-service against the local CLI
- Issues requiring physical access to an unlocked machine with an active session
- Social engineering

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

## Security Design

See the **Security Model** section in [README.md](README.md) for details on the cryptographic architecture.

## Acknowledgments

We appreciate responsible disclosure. Contributors who report valid vulnerabilities will be credited in release notes (unless they prefer anonymity).
