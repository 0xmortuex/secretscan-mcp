# Changelog

## 0.1.0 - 2026-11-06

First release.

- Tools: `scan_tree`, `scan_history`, `check_gitignore`, `explain_finding`, `suggest_remediation`, `make_baseline`.
- 19 rules: AWS, GitHub, GitLab, Slack, Stripe, Google, Anthropic, OpenAI, npm, PyPI, SendGrid, JWT, PEM private
  keys, passwords in URLs, and generic high-entropy assignments (entropy, character-class and placeholder filters).
- History walk over a streamed `git log -p -U0`: one finding per distinct secret with the commit that added it and
  the commit that removed it; handles moves, odd file names, diff-header look-alikes and `--all`.
- Redaction by construction: `Finding` has no field for a raw value; previews are first 4 chars (16+ char secrets
  only) plus length; a final guard refuses any output or error that still matches a secret pattern.
- `.secretscan-ignore` baseline of fingerprints; invalid lines are errors that never echo the line.
- Remediation text with provider-specific rotation steps and git filter-repo / BFG commands (never executed).
