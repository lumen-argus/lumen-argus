# Contributing to lumen-argus

Thank you for your interest in contributing! Here's everything you need to get started.

## Quick Setup

```bash
git clone https://github.com/slima4/lumen-argus.git
cd lumen-argus
pip install -e .
python3 -m unittest discover -v tests/

# Optional: install pre-commit hooks (auto-runs Ruff lint + format on every commit)
brew install pre-commit   # or: pip install pre-commit
pre-commit install
```

## Key Constraints

Before writing code, know these rules:

1. **Zero external dependencies** — community edition is Python stdlib only. No exceptions.
2. **`Finding.matched_value` never written to disk** — not in logs, audit, metrics, or DB.
3. **File permissions `0600`** — all sensitive files (logs, audit, analytics DB, license keys).
4. **Dashboard uses DOM APIs** — no raw HTML injection with user data. Use `textContent` and `createElement`.

## Submitting Changes

1. Fork the repo and create a branch
2. Make your changes
3. Run tests: `python3 -m unittest discover -v tests/`
4. Commit with [Conventional Commits](https://www.conventionalcommits.org/) format:
   ```
   feat(detection): add custom regex rules
   fix(proxy): handle timeout on large payloads
   ```
5. Open a pull request

## What to Work On

- Issues labeled [`good first issue`](https://github.com/slima4/lumen-argus/labels/good%20first%20issue) are a great starting point
- Check [open issues](https://github.com/slima4/lumen-argus/issues) for feature requests and bugs

## Security Vulnerabilities

**Do NOT open a public issue.** See [SECURITY.md](SECURITY.md) for responsible disclosure.

## Full Guide

See the [Contributing Guide](https://slima4.github.io/lumen-argus/docs/development/contributing/) for detailed instructions on code style, project structure, testing, and documentation.
