# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

lumen-argus is a transparent HTTP proxy that sits between AI coding tools (Claude Code, Copilot, Cursor) and their API providers, scanning outbound requests for sensitive data (secrets, PII, proprietary code) and taking configurable actions: block, redact, alert, or log.

Open-core model: Community (free/MIT, Python stdlib only) → Pro → Enterprise.

## Commands

```bash
# Run the proxy
python3 -m lumen_argus                          # default port 8080
python3 -m lumen_argus --port 9090              # custom port
python3 -m lumen_argus --config path/to/config.yaml

# Run all tests
python3 -m unittest discover -v tests/

# Run a single test file
python3 -m unittest tests/test_secrets_detector.py

# Run a single test
python3 -m unittest tests.test_secrets_detector.TestSecretsDetector.test_aws_access_key

# Install as CLI tool
pip install -e .
lumen-argus --help
```

## Architecture

The system is a pipeline with four stages, plus a dashboard and analytics store:

1. **Proxy Server** (`lumen_argus/proxy.py`) — `ThreadingHTTPServer`-based HTTP proxy, binds to `127.0.0.1` by default (use `--host 0.0.0.0` for Docker). Receives plain HTTP, forwards HTTPS to upstream AI providers. Uses `read1()` for SSE streaming passthrough.
2. **Scanner Pipeline** (`lumen_argus/pipeline.py`) — Orchestrates extraction → detection → policy evaluation. `RequestExtractor` (`lumen_argus/extractor.py`) parses Anthropic/OpenAI/Gemini JSON formats into `ScanField` objects. Detectors run sequentially on extracted fields. After scanning, records findings to the analytics store.
3. **Policy Engine** (`lumen_argus/policy.py`) — Evaluates findings against configured rules. Action priority: `block > redact > alert > log`. Per-detector action overrides via config.
4. **Audit Logger** (`lumen_argus/audit.py`) — Thread-safe JSONL writer to `~/.lumen-argus/audit/guard-{timestamp}.jsonl` with `0o600` permissions. `matched_value` is never written to disk.
5. **Dashboard** (`lumen_argus/dashboard/`) — stdlib `http.server` on port 8081 (configurable). Single-page app with 4 functional pages (Dashboard, Findings, Audit, Settings) and 4 locked Pro placeholders. Supports password auth, sessions, CSRF, SSE real-time updates, and plugin extension via `registerPage()` JS API.
6. **Analytics Store** (`lumen_argus/analytics/store.py`) — SQLite-backed findings storage with thread-local connections, WAL mode, `0o600` permissions. Tables: `findings`, `schema_version`. Pro extends with additional tables via subclassing.

### Key Module Relationships

- `lumen_argus/models.py` — All shared dataclasses (`Finding`, `ScanField`, `ScanResult`, `AuditEntry`). No imports from other lumen_argus modules.
- `lumen_argus/patterns/` — Compiled regex patterns. `secrets_patterns.py` (30+ patterns) and `pii_patterns.py` (8 patterns with validators).
- `lumen_argus/detectors/` — `BaseDetector` ABC in `__init__.py`. Implementations: `secrets.py` (regex + entropy sweep), `pii.py` (regex + Luhn/SSN/IP validation), `proprietary.py` (file patterns + keywords).
- `lumen_argus/config.py` — Bundled minimal YAML-subset parser (no PyYAML dependency). Handles mappings, sequences, scalars, comments. Includes `DashboardConfig` and `AnalyticsConfig` dataclasses.
- `lumen_argus/extensions.py` — Open-core boundary. Pro extends (not replaces) via hooks: dashboard pages, CSS, API, analytics store, SSE broadcaster, auth providers. `clear_dashboard_pages()` lets Pro reset extensions on SIGHUP for license state changes. Plugin `js` is trusted code (entry-point only); `html` is sanitized client-side via `_safeInjectHTML`.
- `lumen_argus/dashboard/server.py` — HTTP server with auth, sessions, CSRF, plugin API chain, SSE streaming.
- `lumen_argus/dashboard/api.py` — Community read-only API endpoints. Known Pro endpoints return 402 (not 404).
- `lumen_argus/dashboard/html.py` — Assembles SPA from static files at import time. Plugin CSS/JS injected via `</style>` and `</body>` replacement.
- `lumen_argus/dashboard/static/` — Separate HTML, CSS, and JS files. JS modules: core.js, dashboard.js, findings.js, audit.js, settings.js, init.js.

## Key Constraints

- **Community Edition must be Python stdlib only** — zero external dependencies. This is a core differentiator. The YAML parser is bundled in `config.py`, SQLite via stdlib `sqlite3`.
- Proxy binds to `127.0.0.1` by default. Use `--host 0.0.0.0` for Docker. Non-loopback binds log a warning.
- Performance target: < 50ms scanning overhead per request. All regex patterns compiled at import time.
- Config lives at `~/.lumen-argus/config.yaml` or project-level `.lumen-argus.yaml`. Project config can only be MORE restrictive than global.
- `Finding.matched_value` is kept in memory only — never serialized to audit logs or analytics DB (prevents secondary exfiltration).
- Dashboard static files are separate files assembled at import time — never a single Python string. Pro extends via `registerPage()` JS API, not by replacing HTML.

## Provider Integration

AI tools connect by setting their base URL env var to the proxy:
- `ANTHROPIC_BASE_URL=http://localhost:PORT`
- `OPENAI_BASE_URL=http://localhost:PORT`
- `GEMINI_BASE_URL=http://localhost:PORT`

Provider auto-detection uses path prefix (`/v1/messages` → Anthropic, `/v1/chat/completions` → OpenAI) and headers (`x-api-key`, `anthropic-version`).

## Detection Details

- **Secrets**: 30+ regex patterns (AWS, GitHub, Anthropic, OpenAI, Google, Stripe, Slack, JWT, DB URLs, PEM keys, etc.) plus Shannon entropy > 4.5 bits/char near secret-related keywords.
- **PII**: Email, SSN (range validation), credit cards (Luhn), phone numbers, IP addresses (excluding private ranges), IBAN, passport numbers.
- **Proprietary**: File pattern blocklist (`.pem`, `.key`, `.env`, etc.) and keyword detection (`CONFIDENTIAL`, `TRADE SECRET`, etc.).

## Redaction Format

```
[REDACTED:detector_type]  e.g., [REDACTED:aws_secret_key], [REDACTED:ssn], [REDACTED:email]
```
Note: Redaction action is Pro-only. In Community Edition, `redact` downgrades to `alert`.

## Dashboard

Community dashboard on port 8081 (configurable via `dashboard.port`):
- **5 functional pages**: Dashboard (stats/charts), Findings (paginated table), Audit (log viewer), Settings (config display, license activation), Notifications (freemium: 1 channel without license, unlimited with Pro)
- **3 locked Pro placeholders**: Rules, Patterns, Allowlists — each shows upgrade prompt
- **Notifications**: Community owns the page, DB (notification_channels table), and CRUD API. Pro registers channel types, notifier builder, dispatcher, and channel limit via extension hooks. Without Pro, YAML channels are visible read-only with a dispatch warning. Field name is `type` everywhere (not `channel_type`).
- **Extension model**: Pro calls `registry.register_dashboard_pages()` to unlock placeholders. Community JS exposes `registerPage()` API. `clear_dashboard_pages()` resets on SIGHUP for license transitions. Notification hooks: `register_channel_types()`, `set_notifier_builder()`, `set_dispatcher()`, `set_channel_limit()`.
- **API**: Read-only GET endpoints + POST `/api/v1/license` + notification CRUD (`/api/v1/notifications/*`). `GET /api/v1/status` returns `tier`, `pro_version`, and `license` (when Pro enriches). Known Pro mutation endpoints return 402 (not 404). Notification channel limit enforced with 409.
- **Auth**: Optional password via `dashboard.password` config or `LUMEN_ARGUS_DASHBOARD_PASSWORD` env var. Sessions (8h), CSRF double-submit cookies. Login redirect validates against CRLF injection.
- **Security**: Plugin `html` sanitized via `_safeInjectHTML` (strips scripts/on* handlers). Plugin `js` is trusted (entry-point only). License keys validated for length/newlines before saving.
- **SSE**: Real-time updates via `/api/v1/live`. Fallback to 5s polling.
- **Analytics**: SQLite at `~/.lumen-argus/analytics.db`. Findings recorded by pipeline after each scan. Pro subclasses to add tables.

## Docker

```bash
# Build and run
docker compose up -d

# Connect Claude Code
ANTHROPIC_BASE_URL=http://localhost:8080 claude

# Dashboard at http://localhost:8081
```

`--host 0.0.0.0` flag enables Docker bind. Data persists in named volume across rebuilds.

## Distribution

Single-package model: `pip install lumen-argus` ships both community and Pro (Cython-compiled). No license key = community features. Valid license key = Pro unlocks.

- **Build**: Pro repo (`lumen-argus-pro`) copies community source, Cython-compiles Pro modules, produces one `lumen-argus` wheel
- **Publish**: Pro CI publishes to public PyPI with Sigstore signing
- **Community repo**: source of truth for community code. Not published to PyPI directly — the Pro build pipeline bundles it
- **TestPyPI**: https://test.pypi.org/project/lumen-argus/ (staging, token in `~/.pypirc`)
- **Docker**: `slima4/lumen-argus` image (single image for both tiers)

## Documentation Site

MkDocs Material at https://slima4.github.io/lumen-argus/ — auto-deployed via GitHub Actions on push to `docs/` or `mkdocs.yml`.

- **Config**: `mkdocs.yml` (teal theme, dark mode default, Inter + JetBrains Mono)
- **Source**: `docs/` directory (markdown)
- **Overrides**: `docs/overrides/` (MkDocs Material custom templates)
- **Landing page**: `landing.html` (standalone HTML, copied to `site/landing.html` during build)
- **CI**: `.github/workflows/docs.yml` (build + deploy to GitHub Pages)
- **Local preview**: `pip install mkdocs-material && mkdocs serve`

## CI/CD

- `.github/workflows/test.yml` — tests (5 Python versions x 2 OS), benchmark, Docker smoke test
- `.github/workflows/docs.yml` — MkDocs build + GitHub Pages deploy
- All workflows: `permissions: contents: read`, concurrency cancel-in-progress
- Pro repo owns wheel build (`build-wheels.yml`) and Docker publish (`build-docker.yml`)
