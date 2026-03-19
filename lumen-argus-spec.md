# lumen-argus — Product Specification

**Version:** 1.0.0-draft
**Date:** 2026-03-14
**Status:** Draft
**License Model:** Open Core (Community + Pro + Enterprise)

---

## 1. Executive Summary

### Problem

AI coding assistants (Claude Code, GitHub Copilot, Cursor, etc.) send your entire codebase to external APIs on every request. This creates three categories of data leak risk:

1. **Secrets** — API keys, database credentials, private keys, tokens embedded in code or config files
2. **PII** — Customer data, employee records, email addresses, SSNs, credit card numbers in source code, test fixtures, or logs
3. **Proprietary code** — Trade secrets, unreleased features, internal algorithms sent to third-party AI providers

Existing solutions are either cloud-only (Cloudflare AI Gateway), enterprise-priced (Nightfall AI), or require complex infrastructure (LLM Guard with ML dependencies). There is no lightweight, self-hosted, vendor-agnostic proxy that developers can run locally in under 30 seconds.

### Solution

**lumen-argus** is a transparent HTTP proxy that sits between AI coding tools and their API providers. It scans every outbound request for sensitive data and takes configurable actions: block, redact, alert, or log.

```
Developer's AI Tool  ──HTTP──▶  lumen-argus (localhost)  ──HTTPS──▶  AI Provider API
                                       │
                              ┌────────┴────────┐
                              │ Detection Engine │
                              │  ┌─────────────┐ │
                              │  │  Secrets     │ │
                              │  │  PII         │ │
                              │  │  Proprietary │ │
                              │  └─────────────┘ │
                              └────────┬────────┘
                                       │
                              Actions: block │ redact │ alert │ log
                                       │
                                       ▼
                              Audit Log (JSONL)
```

### Positioning

| | lumen-argus | Cloudflare AI Gateway | Nightfall AI | LLM Guard |
|---|---|---|---|---|
| Self-hosted | Yes | No (cloud) | No (SaaS) | Yes |
| Vendor-agnostic | Yes | Yes | Yes | Yes |
| Zero dependencies (free tier) | Yes | N/A | N/A | No (ML models) |
| Setup time | < 30 seconds | Minutes | Days | Hours |
| Open source | Core engine | No | No | Yes |
| Local-only option | Yes | No | No | Yes |
| Price (basic) | Free | Free tier | Enterprise | Free |

---

## 2. Architecture

### System Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                        lumen-argus                           │
│                                                                 │
│  ┌──────────┐    ┌────────────┐    ┌──────────┐    ┌────────┐  │
│  │  Proxy    │───▶│  Scanner   │───▶│  Policy  │───▶│ Action │  │
│  │  Server   │    │  Pipeline  │    │  Engine  │    │ Handler│  │
│  └──────────┘    └────────────┘    └──────────┘    └────────┘  │
│       │               │                │               │        │
│       │          ┌────┴────┐      ┌────┴────┐    ┌────┴────┐   │
│       │          │ Secrets │      │  Rules  │    │  Block  │   │
│       │          │ PII     │      │  Config │    │  Redact │   │
│       │          │ Custom  │      │  (YAML) │    │  Alert  │   │
│       │          └─────────┘      └─────────┘    │  Log    │   │
│       │                                          └─────────┘   │
│       ▼                                                         │
│  ┌──────────┐                                                   │
│  │  Audit   │                                                   │
│  │  Logger  │──▶ JSONL audit trail                              │
│  └──────────┘                                                   │
└─────────────────────────────────────────────────────────────────┘
```

### Components

#### 2.1 Proxy Server

Transparent HTTP forward proxy based on Python's `http.server.ThreadingHTTPServer`.

- Binds to `127.0.0.1` (localhost only, never `0.0.0.0`)
- Receives plain HTTP from AI tools configured via `*_BASE_URL` environment variables
- Forwards to upstream AI provider over HTTPS
- SSE streaming passthrough using `read1()` for non-blocking chunk forwarding
- Thread-safe request handling with `daemon_threads = True`

**Supported AI providers:**

| Provider | Environment Variable |
|---|---|
| Anthropic (Claude Code) | `ANTHROPIC_BASE_URL=http://localhost:PORT` |
| OpenAI (Copilot, ChatGPT) | `OPENAI_BASE_URL=http://localhost:PORT` |
| Google (Gemini) | `GEMINI_BASE_URL=http://localhost:PORT` |
| Any HTTPS API | Configure tool's base URL to proxy |

#### 2.2 Scanner Pipeline

Request bodies are scanned before forwarding. The pipeline runs detectors in order of priority:

```
Request Body (JSON)
    │
    ├──▶ Extract scannable fields:
    │      • system prompt text
    │      • message contents (user + assistant)
    │      • tool_result contents (file reads, command output)
    │
    ├──▶ Run detectors (parallel):
    │      ├── Secrets Detector
    │      ├── PII Detector
    │      └── Custom Rules Detector
    │
    ├──▶ Aggregate findings with severity
    │
    └──▶ Apply policy (block / redact / alert / log)
```

**Performance target:** < 50ms scanning overhead per request for regex-based detection.

#### 2.3 Audit Logger

Every request produces an audit log entry regardless of detection outcome:

```json
{
  "timestamp": "2026-03-14T10:30:00.123Z",
  "request_id": 1,
  "provider": "anthropic",
  "model": "claude-opus-4-6",
  "action": "alert",
  "findings": [
    {
      "detector": "secrets",
      "type": "aws_access_key",
      "severity": "critical",
      "location": "messages[12].content",
      "value_preview": "AKIA****EXAMPLE",
      "action_taken": "alert"
    }
  ],
  "scan_duration_ms": 12,
  "request_tokens": 45000,
  "passed": true
}
```

Log files: `~/.lumen-argus/audit/guard-{YYYYMMDD-HHMMSS}.jsonl`
Permissions: `0o600` (owner read/write only)

---

## 3. Detection Engine

### 3.1 Secrets Detection

**Approach:** Regex pattern matching + Shannon entropy analysis

#### Built-in Patterns (Community Edition)

| Category | Pattern | Example |
|---|---|---|
| AWS Access Key | `AKIA[0-9A-Z]{16}` | `AKIAIOSFODNN7EXAMPLE` |
| AWS Secret Key | High-entropy string near `aws_secret` | `wJalrXUtnFEMI/K7MDENG/...` |
| GitHub Token | `gh[ps]_[A-Za-z0-9_]{36,}` | `ghp_xxxxxxxxxxxx` |
| Anthropic API Key | `sk-ant-[a-zA-Z0-9-_]{80,}` | `sk-ant-api03-...` |
| OpenAI API Key | `sk-[a-zA-Z0-9]{20,}` | `sk-proj-...` |
| Google API Key | `AIza[0-9A-Za-z_-]{35}` | `AIzaSyA...` |
| Private Key (PEM) | `-----BEGIN (RSA\|EC\|DSA\|OPENSSH) PRIVATE KEY-----` | PEM block |
| JWT | `eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+` | `eyJhbG...` |
| Database URL | `(postgres\|mysql\|mongodb\|redis)://[^\\s]+@` | `postgres://user:pass@host` |
| Generic Password | `(password\|passwd\|pwd)\s*[:=]\s*['"][^'"]{8,}` | `password = "hunter2"` |
| Generic API Key | `(api[_-]?key\|apikey\|secret[_-]?key)\s*[:=]\s*['"][^'"]{16,}` | `api_key = "abc..."` |
| Slack Token | `xox[bprs]-[0-9a-zA-Z-]+` | `xoxb-...` |
| Stripe Key | `[sr]k_(test\|live)_[0-9a-zA-Z]{24,}` | `sk_live_...` |

**Entropy Analysis:**

For unstructured strings, calculate Shannon entropy. Strings with entropy > 4.5 bits/char near keywords like `key`, `secret`, `token`, `password` are flagged as potential secrets.

```python
def shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string."""
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    return -sum((f/length) * log2(f/length) for f in freq.values())
```

#### Extended Patterns (Pro Edition)

- 1,600+ patterns from [Secrets-Patterns-DB](https://github.com/mazen160/secrets-patterns-db)
- Context-aware detection (variable name + value correlation)
- Multi-line pattern matching (certificates, key blocks)
- Historical pattern learning (flag recurring secrets across sessions)

### 3.2 PII Detection

#### Regex-Based (Community Edition)

| Type | Pattern | Validation |
|---|---|---|
| Email | `[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}` | Domain format check |
| SSN (US) | `\b\d{3}-\d{2}-\d{4}\b` | Range validation (not 000, 666, 900+) |
| Credit Card | `\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b` | Luhn algorithm validation |
| Phone (US) | `\b(\+1)?[\s.-]?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b` | Area code validation |
| Phone (Intl) | `\+\d{1,3}[\s.-]?\d{4,14}` | Country code check |
| IP Address | `\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b` | Exclude 127.x, 0.x, 10.x |
| IBAN | `\b[A-Z]{2}\d{2}[A-Z0-9]{4,30}\b` | Country-specific format |
| Passport (US) | `\b[A-Z]\d{8}\b` | Context-required |

#### NLP-Based (Pro Edition)

Uses [Microsoft Presidio](https://github.com/microsoft/presidio) + SpaCy NER models for:

- Person names (first, last, full)
- Physical addresses
- Organization names
- Medical record numbers
- Date of birth patterns
- Context-dependent detection (e.g., "John" alone vs "Patient: John Smith, DOB: 01/15/1990")

**Supported languages:** English, Spanish, French, German, Italian, Portuguese, Dutch

### 3.3 Proprietary Code Detection

#### File Pattern Blocklist (Community Edition)

Block content from sensitive file types from being sent to AI providers:

```yaml
# Default blocklist
file_patterns:
  critical:
    - "*.pem"
    - "*.key"
    - "*.p12"
    - "*.pfx"
    - "id_rsa*"
    - "*.env"
    - "*.env.*"
    - ".npmrc"
    - ".pypirc"
    - "credentials.json"
    - "service-account*.json"
    - "*secret*"
  warning:
    - "*.sqlite"
    - "*.db"
    - "*.sql"
    - "*dump*"
```

#### Keyword Detection (Community Edition)

Scan for markers indicating proprietary content:

```yaml
keywords:
  critical:
    - "CONFIDENTIAL"
    - "PROPRIETARY"
    - "TRADE SECRET"
    - "DO NOT DISTRIBUTE"
    - "INTERNAL ONLY"
    - "NDA REQUIRED"
  warning:
    - "DRAFT"
    - "PRE-RELEASE"
    - "UNRELEASED"
```

#### Advanced Code Protection (Enterprise Edition)

- Repository allowlist/blocklist (only permit scanning specific repos)
- License header detection and classification
- Code fingerprinting (detect proprietary algorithms by structure, not keywords)
- Integration with internal code classification systems
- Data residency enforcement (block sending to non-approved regions)

---

## 4. Actions

Each detection finding triggers a configurable action:

### 4.1 Action Types

| Action | Behavior | Use Case |
|---|---|---|
| **log** | Record finding in audit log, allow request | Monitoring, baseline establishment |
| **alert** | Log + send notification (CLI, webhook), allow request | Awareness without blocking |
| **redact** | Replace detected content with placeholder, forward modified request | Allow work to continue safely |
| **block** | Reject request with HTTP 403, return error to AI tool | Hard enforcement for critical data |

### 4.2 Redaction Format

```
Original: "AWS_SECRET_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
Redacted: "AWS_SECRET_KEY=[REDACTED:aws_secret_key]"

Original: "Patient SSN: 123-45-6789"
Redacted: "Patient SSN: [REDACTED:ssn]"

Original: "Contact: john.smith@company.com"
Redacted: "Contact: [REDACTED:email]"
```

### 4.3 Action Priority

When multiple detectors flag the same content, the highest-severity action wins:

```
block > redact > alert > log
```

### 4.4 CLI Output

```
  lumen-argus — listening on http://127.0.0.1:8080

  #1  POST /v1/messages  opus-4-6  88.3k->1.5k  $0.14  2312ms  PASS
  #2  POST /v1/messages  opus-4-6  90.1k->0.8k  $0.14  1134ms  ALERT  aws_access_key (messages[4])
  #3  POST /v1/messages  opus-4-6  91.2k->2.1k  $0.15  3412ms  BLOCK  private_key (tool_result[2])
  #4  POST /v1/messages  opus-4-6  91.2k->1.2k  $0.15  1823ms  REDACT ssn×2, email×1
```

---

## 5. Open-Core Tier Breakdown

### 5.1 Community Edition (Free, Open Source, MIT License)

**Target:** Individual developers, open-source projects, small teams

| Feature | Included |
|---|---|
| Transparent HTTP proxy | Yes |
| Vendor-agnostic (Claude, OpenAI, Gemini, etc.) | Yes |
| Secrets detection (30+ built-in regex patterns) | Yes |
| PII detection (regex-based: email, SSN, CC, phone) | Yes |
| File pattern blocklist | Yes |
| Keyword detection | Yes |
| Shannon entropy analysis | Yes |
| Actions: log, alert (CLI), block | Yes |
| JSONL audit log | Yes |
| CLI terminal output | Yes |
| Python stdlib only (zero dependencies) | Yes |
| Configuration via YAML | Yes |
| Single-user, single-machine | Yes |

**Not included:** Redaction, custom rules, web dashboard, webhooks, NLP-based PII, team features, compliance reports.

### 5.2 Pro Edition ($99-299/month per team)

**Target:** Development teams, startups, companies with compliance requirements

| Feature | Included |
|---|---|
| Everything in Community | Yes |
| Extended secrets patterns (1,600+ from Secrets-Patterns-DB) | Yes |
| NLP-based PII detection (Presidio + SpaCy) | Yes |
| Custom detection rules (YAML DSL) | Yes |
| Redaction action | Yes |
| Web dashboard (localhost) | Yes |
| Real-time alerts via webhooks (Slack, Teams, PagerDuty) | Yes |
| Detection rule sharing across team | Yes |
| Historical analytics and trend reporting | Yes |
| Multi-provider support in single instance | Yes |
| Priority email support | Yes |
| Allowlist/blocklist management UI | Yes |

**Pricing:**

| Plan | Price | Included |
|---|---|---|
| Pro Small | $99/mo | Up to 5 developers |
| Pro Team | $199/mo | Up to 20 developers |
| Pro Business | $299/mo | Up to 50 developers |

### 5.3 Enterprise Edition (Custom Pricing)

**Target:** Large organizations, regulated industries, compliance-driven teams

| Feature | Included |
|---|---|
| Everything in Pro | Yes |
| SSO / SAML / OIDC authentication | Yes |
| RBAC (role-based access control) | Yes |
| Compliance report generation (SOC 2, HIPAA, GDPR, PCI DSS) | Yes |
| SIEM integration (Splunk, Datadog, Elastic, Sentinel) | Yes |
| Centralized policy management (multi-team) | Yes |
| On-premise / air-gapped deployment | Yes |
| Code fingerprinting and classification | Yes |
| Data residency enforcement | Yes |
| Custom detector development (Python API) | Yes |
| Audit log export (S3, GCS, Azure Blob) | Yes |
| Dedicated support engineer | Yes |
| SLA (99.9% uptime for hosted dashboard) | Yes |
| Training and onboarding | Yes |

**Pricing:** Custom, typically $2,000–10,000+/month based on developer count and deployment model.

---

## 6. Configuration

### 6.1 Configuration File

Location: `~/.lumen-argus/config.yaml` (or project-level `.lumen-argus.yaml`)

```yaml
# lumen-argus configuration
version: "1"

# Proxy settings
proxy:
  port: 8080
  bind: "127.0.0.1"
  upstream:
    anthropic: "https://api.anthropic.com"
    openai: "https://api.openai.com"

# Global default action
default_action: alert  # log | alert | redact | block

# Detection settings
detectors:
  secrets:
    enabled: true
    action: block          # override default for secrets
    severity_threshold: warning  # minimum severity to act on
    entropy_threshold: 4.5
    patterns:
      # Additional custom patterns
      - name: "internal_service_token"
        pattern: "svc_[a-zA-Z0-9]{32}"
        severity: critical
        action: block

  pii:
    enabled: true
    action: alert
    types:
      email: alert
      ssn: block
      credit_card: block
      phone: log
      # NLP-based (Pro only)
      person_name: alert
      address: alert

  proprietary:
    enabled: true
    action: alert
    keywords:
      critical:
        - "CONFIDENTIAL"
        - "TRADE SECRET"
      warning:
        - "INTERNAL ONLY"
    file_patterns:
      block:
        - "*.pem"
        - "*.key"
        - "*.env"

# Allowlists — never flag these
allowlists:
  # Known safe patterns (e.g., example keys in docs)
  secrets:
    - "AKIAIOSFODNN7EXAMPLE"     # AWS example key
    - "sk-ant-api03-example"     # Anthropic docs example
  # Known safe email domains
  pii:
    - "*@example.com"
    - "*@test.local"
  # Safe file paths
  paths:
    - "test/**"
    - "fixtures/**"
    - "*.test.*"

# Notifications (Pro+)
notifications:
  slack:
    webhook_url: "https://hooks.slack.com/services/..."
    min_severity: critical
  webhook:
    url: "https://internal.company.com/security/alerts"
    headers:
      Authorization: "Bearer ${GUARD_WEBHOOK_TOKEN}"

# Audit settings
audit:
  log_dir: "~/.lumen-argus/audit"
  retention_days: 90
  include_request_summary: true   # log token counts, model, etc.
  redact_findings_in_log: false   # true = hash detected values in log
```

### 6.2 Rule DSL (Pro Edition)

Custom rules beyond built-in detectors:

```yaml
custom_rules:
  - name: "internal_api_endpoint"
    description: "Block internal API URLs from being sent to AI"
    detector: regex
    pattern: "https?://(internal|staging|dev)\\.company\\.com[/\\s]"
    scope: [messages, system, tool_results]
    severity: critical
    action: redact
    replacement: "[REDACTED:internal_url]"

  - name: "employee_id"
    description: "Detect employee ID format"
    detector: regex
    pattern: "EMP-\\d{6}"
    severity: warning
    action: alert

  - name: "large_data_blob"
    description: "Block unusually large base64 data"
    detector: size
    max_field_size_kb: 500
    severity: warning
    action: alert
```

### 6.3 Project-Level Overrides

Teams can commit `.lumen-argus.yaml` to their repo root to enforce project-specific rules:

```yaml
# .lumen-argus.yaml (in project root)
extends: default  # inherit global config

detectors:
  proprietary:
    keywords:
      critical:
        - "PATIENT_DATA"    # healthcare project
        - "PHI"
    file_patterns:
      block:
        - "migrations/*.sql"
        - "seeds/**"
```

Project config merges with global config. Project rules can only be **more restrictive** than global (cannot downgrade `block` to `log`).

---

## 7. Compliance Mapping

### 7.1 GDPR (General Data Protection Regulation)

| GDPR Requirement | lumen-argus Feature | Tier |
|---|---|---|
| Data minimization (Art. 5(1)(c)) | PII detection + redaction before sending to AI | Pro |
| Right to erasure (Art. 17) | Audit log with finding locations for data mapping | Community |
| Records of processing (Art. 30) | JSONL audit trail of all AI API interactions | Community |
| Data Protection Impact Assessment | Compliance report generation | Enterprise |
| Lawful basis documentation | Audit log metadata (who, what, when, why) | Community |
| Cross-border transfer safeguards | Data residency enforcement | Enterprise |

### 7.2 SOC 2 (Type II)

| SOC 2 Trust Principle | lumen-argus Feature | Tier |
|---|---|---|
| Security: Access controls | RBAC, SSO/SAML integration | Enterprise |
| Security: System monitoring | Real-time detection + alerting | Pro |
| Availability: System operations | Health checks, uptime SLA | Enterprise |
| Processing Integrity: Complete, accurate processing | Audit trail with scan results for every request | Community |
| Confidentiality: Classified data protection | Secrets + PII detection, blocking, redaction | Community+ |
| Privacy: PII handling | PII detection, redaction, audit logging | Pro |

### 7.3 HIPAA (Health Insurance Portability and Accountability Act)

| HIPAA Requirement | lumen-argus Feature | Tier |
|---|---|---|
| PHI safeguards (§164.312) | PHI pattern detection (MRN, DOB, diagnosis codes) | Pro |
| Access controls (§164.312(a)) | RBAC, authentication | Enterprise |
| Audit controls (§164.312(b)) | Complete audit trail of all AI interactions | Community |
| Transmission security (§164.312(e)) | HTTPS forwarding, localhost-only binding | Community |
| Incident response | Real-time alerts for PHI detection | Pro |
| BAA compliance | On-premise deployment, no data leaves org network | Enterprise |

### 7.4 PCI DSS (Payment Card Industry Data Security Standard)

| PCI DSS Requirement | lumen-argus Feature | Tier |
|---|---|---|
| Req 3: Protect stored cardholder data | Credit card detection + blocking | Community |
| Req 4: Encrypt transmission | HTTPS forwarding to provider | Community |
| Req 7: Restrict access | RBAC for policy management | Enterprise |
| Req 10: Track and monitor access | Audit logging with cardholder data findings | Community |
| Req 12: Security policy | Configurable detection policies | Community |

---

## 8. API and Integrations

### 8.1 Management API (Pro+)

REST API on a separate port for configuration and monitoring:

```
GET    /api/v1/status              # proxy health and stats
GET    /api/v1/findings            # list recent findings
GET    /api/v1/findings/:id        # finding details
GET    /api/v1/stats               # detection statistics
GET    /api/v1/rules               # list active rules
PUT    /api/v1/rules/:name         # update rule
POST   /api/v1/rules               # create custom rule
DELETE /api/v1/rules/:name         # delete custom rule
GET    /api/v1/audit               # query audit log
POST   /api/v1/allowlist           # add allowlist entry
GET    /api/v1/compliance/:framework  # generate compliance report
```

### 8.2 Webhook Events (Pro+)

```json
{
  "event": "finding.critical",
  "timestamp": "2026-03-14T10:30:00.123Z",
  "guard_instance": "dev-laptop-01",
  "finding": {
    "detector": "secrets",
    "type": "aws_secret_key",
    "severity": "critical",
    "action_taken": "block",
    "provider": "anthropic",
    "model": "claude-opus-4-6"
  }
}
```

**Webhook targets:**
- Slack (formatted message with severity colors)
- Microsoft Teams (adaptive card)
- PagerDuty (incident creation for critical)
- Generic HTTP webhook
- Email (via SMTP or SendGrid)

### 8.3 SIEM Integration (Enterprise)

Export formats:
- **Syslog** (RFC 5424) — for Splunk, QRadar
- **CEF** (Common Event Format) — for ArcSight
- **OCSF** (Open Cybersecurity Schema Framework) — for AWS Security Lake, Datadog
- **JSON over HTTPS** — for Elastic, Datadog, Sentinel

### 8.4 Web Dashboard (Pro+)

Localhost web interface for monitoring and configuration:

```
http://localhost:8081  (separate port from proxy)
```

**Pages:**
- **Live Feed** — real-time stream of requests and findings
- **Analytics** — detection trends, top finding types, provider breakdown
- **Rules** — view, edit, create detection rules
- **Allowlists** — manage safe patterns
- **Audit Log** — searchable, filterable history
- **Settings** — proxy config, notifications, integrations
- **Compliance** — generate and view compliance reports

---

## 9. Competitive Analysis

### 9.1 Feature Comparison Matrix

| Feature | lumen-argus (Community) | lumen-argus (Pro) | Cloudflare AI Gateway | Nightfall AI | LLM Guard | AIDLP |
|---|:-:|:-:|:-:|:-:|:-:|:-:|
| Self-hosted | Yes | Yes | No | No | Yes | Yes |
| Zero dependencies | Yes | No | N/A | N/A | No | No |
| Setup time | < 30s | < 5 min | Minutes | Days | Hours | Hours |
| Secrets detection | 30+ patterns | 1,600+ patterns | Limited | Yes | Limited | Yes |
| PII detection (regex) | Yes | Yes | Predefined | Yes | Yes | Yes |
| PII detection (NLP) | No | Yes | No | Yes | Yes | Yes |
| Custom rules | No | Yes (YAML DSL) | Limited | Yes | Yes | Yes |
| Redaction | No | Yes | No | Yes | Yes | Yes |
| Web dashboard | No | Yes | Yes | Yes | No | No |
| Webhooks/alerts | CLI only | Slack, Teams, etc. | Yes | Yes | No | No |
| SIEM integration | No | No | Logpush | Yes | No | No |
| Compliance reports | No | No | No | Yes | No | No |
| SSO/RBAC | No | No | Yes | Yes | No | No |
| Vendor-agnostic | Yes | Yes | Yes | Yes | Yes | Partial |
| Price | Free | $99-299/mo | Free tier | Enterprise | Free | Free |
| License | MIT | Commercial | Proprietary | Proprietary | MIT | MIT |

### 9.2 Differentiation

1. **Developer-first UX:** Install and run in one command. No cloud accounts, no config portals, no infrastructure. Developers actually use it because it's frictionless.

2. **Zero-dependency community edition:** Python stdlib only. No ML models to download, no Docker containers, no GPU requirements. Works on any machine with Python 3.8+.

3. **Built by AI tool users:** Born from real Claude Code session monitoring (ClaudeTUI). Deep understanding of how AI coding tools actually structure API calls, what data leaks look like in practice.

4. **Local-first privacy:** All scanning happens on your machine. No data sent to any third party. The DLP tool itself doesn't create a new data leak vector.

5. **Open core with real value in free tier:** The community edition is genuinely useful, not crippled. Core detection + blocking + audit logging — enough for most individual developers and small teams.

---

## 10. Roadmap

### Phase 1: MVP (Community Edition) — Month 1-2

**Goal:** Working proxy with basic secrets and PII detection

- [ ] Fork proxy architecture from ClaudeTUI sniffer
- [ ] Implement secrets detector (30 built-in regex patterns)
- [ ] Implement PII detector (email, SSN, CC, phone — regex-based)
- [ ] Implement file pattern and keyword detection
- [ ] Shannon entropy analysis for unstructured secrets
- [ ] Actions: log, alert (CLI), block
- [ ] YAML configuration file
- [ ] Allowlist support
- [ ] JSONL audit logging
- [ ] CLI terminal output with finding summaries
- [ ] Multi-provider support (Anthropic, OpenAI)
- [ ] README, docs, install script
- [ ] GitHub release, initial marketing

**Deliverable:** Open-source v1.0.0 on GitHub with MIT license

### Phase 2: Pro Edition — Month 3-4

**Goal:** Team features and advanced detection

- [ ] Extended secrets patterns (Secrets-Patterns-DB integration)
- [ ] NLP-based PII detection (Presidio + SpaCy)
- [ ] Custom rule DSL (YAML)
- [ ] Redaction action
- [ ] Web dashboard (localhost, single-page app)
- [ ] Webhook notifications (Slack, Teams, generic HTTP)
- [ ] Historical analytics and trend charts
- [ ] License key validation system
- [ ] Payment integration (Stripe)
- [ ] Documentation site

**Deliverable:** Pro v1.0 release, paid subscriptions active

### Phase 3: Enterprise Edition — Month 5-8

**Goal:** Enterprise-grade security and compliance

- [ ] SSO / SAML / OIDC integration
- [ ] RBAC (role-based access control)
- [ ] Compliance report generation (SOC 2, HIPAA, GDPR, PCI DSS)
- [ ] SIEM integration (Syslog, CEF, OCSF)
- [ ] Centralized policy management
- [ ] On-premise deployment packaging
- [ ] Code fingerprinting engine
- [ ] Data residency enforcement
- [ ] Custom detector Python API
- [ ] Audit log cloud export (S3, GCS, Azure)
- [ ] Enterprise sales infrastructure
- [ ] SOC 2 Type II certification for hosted dashboard

**Deliverable:** Enterprise v1.0, first enterprise customer

### Phase 4: Scale — Month 9-12

- [ ] Browser extension (catch ChatGPT, Claude.ai web usage)
- [ ] IDE plugin integrations (VS Code, JetBrains)
- [ ] Multi-language NLP models (beyond English)
- [ ] Machine learning-based anomaly detection
- [ ] API marketplace for community-built detectors
- [ ] Partner integrations (MDM, CASB, SASE platforms)

---

## Appendix A: Terminology

| Term | Definition |
|---|---|
| **DLP** | Data Loss Prevention — technology to detect and prevent data exfiltration |
| **PII** | Personally Identifiable Information — data that can identify an individual |
| **PHI** | Protected Health Information — health-related PII under HIPAA |
| **SSE** | Server-Sent Events — streaming protocol used by AI APIs |
| **SIEM** | Security Information and Event Management — centralized security log analysis |
| **RBAC** | Role-Based Access Control — authorization model based on user roles |
| **CEF** | Common Event Format — standardized log format for security events |
| **OCSF** | Open Cybersecurity Schema Framework — vendor-agnostic security data schema |
| **NER** | Named Entity Recognition — NLP technique for identifying entities in text |
| **BAA** | Business Associate Agreement — HIPAA contract for handling PHI |

## Appendix B: Secret Pattern Sources

- [Secrets-Patterns-DB](https://github.com/mazen160/secrets-patterns-db) — 1,600+ patterns (MIT licensed)
- [Gitleaks](https://github.com/gitleaks/gitleaks) — rule format reference
- [GitGuardian](https://docs.gitguardian.com/) — detection methodology reference
- [TruffleHog](https://github.com/trufflesecurity/trufflehog) — entropy + verification approach

## Appendix C: Related Standards

- NIST SP 800-171 (Controlled Unclassified Information)
- ISO 27001 (Information Security Management)
- EDPB AI Privacy Risks Report (April 2025)
- EU AI Act (compliance deadline: August 2, 2026)
