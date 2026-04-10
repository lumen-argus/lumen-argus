# Rule Analysis

The Rule Analysis page detects duplicate, subset, and overlapping detection rules in your ruleset. It uses [crossfire-rules](https://pypi.org/project/crossfire-rules/), an optional corpus-based analysis engine, to generate test strings for each rule and measure how much they overlap.

This helps SecOps/admins clean up redundant rules — reducing scan time, eliminating duplicate alerts, and keeping the ruleset maintainable as it grows.

## Installation

`crossfire-rules` is an optional dependency. Without it, the Rule Analysis tab shows install instructions.

```bash
# Via pip extras (recommended — pulls the pinned version)
pip install lumen-argus-proxy[rules-analysis]

# Or install crossfire-rules directly
pip install crossfire-rules[re2]
```

The `[re2]` extra pulls in `google-re2`, which is required for fast evaluation across large rulesets (1,000+ rules). Without it, evaluation falls back to Python's built-in `re` and is significantly slower.

The Docker image includes `crossfire-rules[re2]` by default — no extra steps needed when running via `docker compose up`.

> **Note:** PyPI also has an unrelated package called `crossfire` (an HTTP scraper). Make sure you install **`crossfire-rules`**, not `crossfire`.

## How it works

When you click **Analyze**, the engine runs four steps:

1. **Load rules** — reads all enabled rules from the DB (community, pro, custom)
2. **Generate corpus** — creates random strings that match each rule's regex pattern (default: 50 strings per rule)
3. **Cross-evaluate** — tests every rule against every other rule's corpus strings to build an overlap matrix
4. **Classify** — categorizes each pair as duplicate, subset, overlap, or disjoint based on match ratios

The analysis runs in a background thread. The dashboard shows live progress with a log terminal streaming each step.

## Understanding results

### Duplicates

Two rules match the same set of strings. Example: `aws_key_v1` and `aws_key_v2` both detect `AKIA[0-9A-Z]{16}` — one is redundant.

**Jaccard score** measures overlap symmetry (0.0 = no overlap, 1.0 = identical). Duplicates have Jaccard >= the configured threshold (default 0.8).

**Action:** Disable the redundant rule. The recommendation tells you which to keep based on tier priority (community > custom > pro).

### Subsets

Rule A's corpus is fully matched by rule B, but not vice versa. Rule B is broader — it catches everything A catches, plus more.

Example: `terraform_cloud_token` is a subset of `generic_secret` — the generic pattern matches all Terraform tokens, but the Terraform pattern doesn't match all generic secrets.

**Action:** This is nuanced. The broader rule catches more, but the specific rule gives better finding names. In a DLP scanner, you often want **both** — the specific rule for precise alerting and the broad rule as a safety net. Use **Review** to compare the patterns, then decide:

- **Disable the subset** if the broad rule's finding name is good enough
- **Dismiss** if you want both rules active (the overlap is intentional)

### Overlaps

Partial overlap — some strings match both rules, but neither fully contains the other. The card shows directional overlap percentages:

- **A→B: 40%** means 40% of rule B's corpus is also matched by rule A
- **B→A: 30%** means 30% of rule A's corpus is also matched by rule B

**Action:** Review both rules. Overlaps are usually expected between related patterns (e.g., `generic_password` and `generic_password_unquoted`). Dismiss if intentional.

### Clusters

Groups of rules that are all connected by overlaps. If rules A, B, and C all overlap with each other, they form a cluster. Useful for identifying families of related patterns that could be consolidated.

## Dashboard actions

### Disable

Disables the recommended rule directly from the analysis page. The rule is toggled off via `PUT /api/v1/rules/:name` with `enabled: false`. The card shows a "resolved" state.

### Review

Opens the Rules page filtered to both rules in the pair (comma-separated search). You can compare patterns, severity, tier, and hit counts side by side.

### Dismiss

Hides the finding — it won't appear in future results until the next analysis. Dismissed pairs are stored in the DB and survive re-analysis. Use this for intentional overlaps you've reviewed and accepted.

## Overlap badges on Rules page

Each rule on the Rules page shows a small badge like `[2 ovr]` if it appears in overlap analysis results. The badge links directly to the Rule Analysis page.

## Configuration

Configure in `config.yaml`:

```yaml
rule_analysis:
  samples: 50           # corpus strings per rule (higher = more stable, slower)
  threshold: 0.8        # overlap fraction for duplicate/subset classification
  seed: 42              # random seed for reproducible results
  auto_on_import: true  # run analysis after rule import
```

### Tuning samples

The `samples` setting controls accuracy vs speed:

| Samples | 55 rules | 1,700 rules | Stability |
|---------|----------|-------------|-----------|
| 30 | ~0.5s | ~30s | Borderline pairs may appear/disappear between runs |
| 50 | ~0.8s | ~50s | Good balance for most deployments |
| 100 | ~1.5s | ~2m | Reliable for compliance reporting |

Lower `samples` means faster analysis but borderline overlaps (near the threshold) may fluctuate between runs. The crossfire classifier warns when confidence intervals are wide — increase samples if you see these warnings.

### Threshold

The `threshold` controls what counts as a duplicate or subset (default 0.8 = 80% overlap). Lower values catch more pairs but increase noise. Higher values only flag near-exact matches.

## Auto-analysis

When `auto_on_import: true` (default), analysis runs automatically in a background thread after:

- Community rules auto-import on first startup
- `lumen-argus rules import` CLI command

The dashboard receives an SSE event when analysis completes and auto-refreshes the Rule Analysis page.

## API endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/rules/analysis` | GET | Get cached results |
| `/api/v1/rules/analysis` | POST | Trigger new analysis (202, background) |
| `/api/v1/rules/analysis/status` | GET | Progress with log streaming (`?since=N`) |
| `/api/v1/rules/analysis/dismiss` | POST | Dismiss a finding pair |

## Pro enhancements

Pro extends the Rule Analysis page with:

- **Quality scoring** — broad pattern detection, specificity analysis
- **Fully redundant rules list** — one-click cleanup
- **Export** — JSON and CSV reports for compliance
- **Auto-dedup on import** — automatically disables Pro rules that duplicate community rules
