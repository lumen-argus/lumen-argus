## Summary

<!-- Brief description of what this PR does -->

## Checklist

- [ ] Tests pass locally (`python -m unittest discover tests/`)
- [ ] No external dependencies added (community edition is stdlib-only)
- [ ] `Finding.matched_value` is never persisted to disk, logs, or DB
- [ ] Dashboard changes use DOM APIs (no raw HTML injection with user data)
- [ ] File permissions are 0600 for any new sensitive files
