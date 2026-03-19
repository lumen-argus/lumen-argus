# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| latest  | Yes       |

## Reporting a Vulnerability

If you discover a security vulnerability in lumen-argus, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

### How to Report

1. Email: **security@lumen-argus.com** (preferred)
2. GitHub: Use [private vulnerability reporting](https://github.com/slima4/lumen-argus/security/advisories/new)

### What to Include

- Description of the vulnerability
- Steps to reproduce
- Impact assessment (what an attacker could do)
- Affected version(s)
- Suggested fix (if any)

### Response Timeline

- **Acknowledgment**: within 48 hours
- **Assessment**: within 7 days
- **Fix**: depends on severity (critical: ASAP, high: 14 days, medium: 30 days)

### Scope

In scope:
- Proxy request handling (bypass, injection, header leaks)
- Dashboard authentication and authorization
- Audit log integrity (matched values must never be persisted)
- CSRF, XSS, or injection in dashboard
- Notification channel credential exposure
- SQLite injection via API inputs
- File permission issues on logs, DB, license keys

Out of scope:
- Denial of service on localhost (proxy is designed for local use)
- Issues requiring physical access to the machine
- Social engineering

### Recognition

We credit reporters in the release notes (unless you prefer anonymity).

## Security Design

See [docs/operations/security.md](docs/operations/security.md) for details on:
- Network security (bind address, TLS)
- Dashboard auth (sessions, CSRF, CRLF protection)
- Data security (matched values never persisted)
- File permissions (0600 on all sensitive files)
- Plugin trust model
