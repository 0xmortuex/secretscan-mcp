"""secretscan-mcp: find committed secrets in a tree and in git history.

Safety design, in one place:
  * No tool returns a raw secret. Findings carry a type, file, line, commit, a
    fingerprint, and "first 4 chars + length" (4 chars only for secrets of 16+).
  * The server never writes a file, never touches the network, and never runs
    anything but read-only git subcommands.
  * Remediation commands are returned as text for a human to run.
"""

from __future__ import annotations

import functools
import subprocess
from collections.abc import Callable
from typing import Any, TypeVar

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations

from . import hygiene, report
from .detect import RULES_BY_ID, Finding, rule_ids
from .remediation import build_checklist, explain_rule
from .scanner import IGNORE_FILE, scan_history as _scan_history
from .scanner import scan_tree as _scan_tree

mcp = MCPServer(
    "secretscan",
    instructions=(
        "Find accidentally committed secrets (API keys, tokens, private keys, passwords in URLs, .env files) "
        "in a project directory and in its git history, and say what to do about them. Every result is "
        "redacted: you will never see a secret value, only its type, file, line, commit, a fingerprint id and "
        "'first 4 chars + length'. Do not ask the user to paste the secret. Typical flow: scan_tree(path) -> "
        "scan_history(path) -> explain_finding(id) -> suggest_remediation(path). The ids are valid until the "
        "server restarts. Rotating the credential is the fix; history rewriting does not un-leak it."
    ),
)

F = TypeVar("F", bound=Callable[..., Any])

# id -> (finding, extra text). Redacted data only.
_known: dict[str, tuple[Finding, str]] = {}

_READ_ONLY = ToolAnnotations(read_only_hint=True, destructive_hint=False, idempotent_hint=True, open_world_hint=False)

# Failures an agent can act on. MCPServer forwards only a ToolError's message, so these are
# re-raised as ToolError with their text intact. Anything else is a bug and stays hidden.
_EXPECTED = (ValueError, KeyError, OSError, subprocess.TimeoutExpired, report.RedactionError)


def tool(fn: F) -> F:
    @functools.wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        try:
            return report.guard(fn(*args, **kwargs))
        except _EXPECTED as e:
            msg = e.args[0] if isinstance(e, KeyError) and e.args else str(e)
            try:
                report.guard(str(msg))  # error text gets the same last-line check as results
            except report.RedactionError as leak:
                raise ToolError(str(leak)) from None
            raise ToolError(str(msg)) from e

    mcp.tool(annotations=_READ_ONLY)(wrapper)
    return fn


def _remember(f: Finding, extra: str = "") -> None:
    _known[f.id] = (f, extra)


@tool
def scan_tree(path: str, max_findings: int = 100) -> str:
    """Scan the files of a project directory for secrets. Read-only; values are redacted.

    Detects AWS, GitHub, GitLab, Slack, Stripe, Google, OpenAI, Anthropic, npm, PyPI and SendGrid keys, JWTs,
    PEM private key blocks, passwords inside URLs, and generic high-entropy values assigned to names like
    password/secret/token/api_key. In a git repository it scans exactly what `git add .` would pick up
    (tracked files plus untracked files that are not ignored), so .gitignore is respected. It skips binaries,
    files over 1 MB, lockfiles and vendored directories (node_modules, vendor, .venv, ...). It does not follow symlinks.

    Each finding shows: severity, id (f-<fingerprint>), rule, file:line, and the value as 'first 4 chars + length'
    (short secrets show no characters). Findings listed in <repo>/.secretscan-ignore are suppressed.

    Args:
        path: project directory (absolute or relative to the server's working directory).
        max_findings: cap on findings listed, highest severity first.
    """
    res = _scan_tree(path)
    for f in res.findings:
        _remember(f)
    return report.tree_report(res, max_findings)


@tool
def scan_history(path: str, max_commits: int = 500, all_branches: bool = False, max_findings: int = 100) -> str:
    """Scan git history for secrets, including ones already deleted from the current files.

    Streams `git log -p` and looks at every added and removed line. Each distinct secret is reported once with
    the commit that added it and, if it is gone from the newest commit, the commit that removed it. REMOVED means
    'not in the current files', NOT 'safe': anyone who cloned in between still has it, so rotate it.

    Args:
        path: a directory inside a git repository.
        max_commits: how many commits to walk back from HEAD (newest first). The report says if older ones were not scanned.
        all_branches: also walk every branch, tag and stash ref (git log --all) instead of only HEAD.
        max_findings: cap on findings listed.
    """
    res = _scan_history(path, max_commits, all_branches)
    for h in res.findings:
        f = h.finding
        extra = f"; added in {h.added_commit or 'before the scanned window'}" + (
            f", removed in {h.removed_commit}" if h.removed_commit else ", still present")
        _remember(f, extra)
    return report.history_report(res, max_findings)


@tool
def check_gitignore(path: str) -> str:
    """Check whether secret-bearing files (.env, *.pem, *.key, id_rsa, credentials.json, *.tfvars, ...) are
    ignored and untracked in a git repository.

    Reports: secret-looking files that ARE tracked (an ignore rule no longer helps; includes the
    `git rm --cached` command as text), untracked-but-not-ignored ones that the next `git add .` would commit,
    common secret file names that no ignore rule covers yet, and tracked files that match .gitignore anyway.
    Looks at file names only; use scan_tree to look inside files.

    Args:
        path: a directory inside a git repository.
    """
    return hygiene.check_gitignore(path)


@tool
def explain_finding(id: str) -> str:
    """Explain a finding: what the credential is, how to rotate or revoke it at the provider (step by step),
    how to check whether it was abused, and why rewriting git history does not un-leak it.

    Args:
        id: a finding id such as f-0123456789abcdef from scan_tree/scan_history (valid until the server restarts),
            or a rule id such as aws-access-key-id or github-token to get the guidance without a finding.
    """
    key = id.strip()
    if not key.startswith("f-") and len(key) == 16:
        key = "f-" + key
    if key in _known:
        f, extra = _known[key]
        return explain_rule(f.rule, f, extra)
    if key in RULES_BY_ID:
        return explain_rule(key)
    raise KeyError(
        f"unknown finding id (a {len(key)}-character value; it is not echoed in case it is a secret). Run scan_tree or scan_history first and pass an id from its output "
        f"(f-<16 hex>; ids are forgotten when the server restarts), or pass a rule id: {', '.join(rule_ids())}."
    )


@tool
def suggest_remediation(path: str, max_commits: int = 500) -> str:
    """Scan a project (working tree and git history, if it is a repository) and return an ORDERED remediation
    checklist: rotate first, look for misuse, remove from the tree, optionally rewrite history, prevent
    recurrence. History rewriting is given as git filter-repo and BFG command text for you to run; this server
    never executes them and never prints the secret values they need (you fill in a replacements file yourself).

    Args:
        path: project directory.
        max_commits: history depth to scan if the directory is a git repository.
    """
    tree = _scan_tree(path)
    hist = None
    if tree.is_git:
        from .gitutil import has_commits

        if has_commits(tree.root):
            hist = _scan_history(path, max_commits, False)
    for f in tree.findings:
        _remember(f)
    if hist is not None:
        for h in hist.findings:
            _remember(h.finding)
    head = f"suggest_remediation: {tree.root}\n{len(tree.findings)} in the tree"
    head += f", {len(hist.findings)} in history" if hist else ", history not scanned (not a git repository or no commits)"
    return head + "\n\n" + build_checklist(tree, hist)


@tool
def make_baseline(path: str, include_history: bool = False, max_commits: int = 500) -> str:
    """Return the lines to put in <repo>/.secretscan-ignore so the CURRENT findings are accepted (a baseline)
    and only new ones are reported later. Only fingerprints are listed, never values. This server does not
    write the file: copy the text into it yourself, after checking each finding really is a false positive
    or already rotated. Accepting a live secret hides it; rotate real ones instead.

    Args:
        path: project directory.
        include_history: also include secrets found in git history.
        max_commits: history depth if include_history is true.
    """
    tree = _scan_tree(path)
    items = [(f.fingerprint, f"{f.rule} {f.path}:{f.line}") for f in tree.findings]
    if include_history:
        items += [(h.finding.fingerprint, f"{h.finding.rule} {h.finding.path}:{h.finding.line} (history)")
                  for h in _scan_history(path, max_commits, False).findings]
    if not items:
        return "Nothing to baseline: no findings."
    seen: set[str] = set()
    lines = []
    for fp, why in items:
        if fp not in seen:
            seen.add(fp)
            lines.append(f"{fp}  # {why}")
    return (f"Add these lines to {IGNORE_FILE} in the repository root (one fingerprint per line, '#' starts a comment):\n\n"
            + "\n".join(lines))


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
