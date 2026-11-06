"""Turn scan results into text for the agent. Nothing here ever sees a raw secret."""

from __future__ import annotations

from .detect import Finding, leaked_rule
from .scanner import HistoryScan, TreeScan

_SEV = {"high": 0, "medium": 1, "low": 2}


class RedactionError(RuntimeError):
    pass


def guard(text: str) -> str:
    """Refuse to return text in which a high-confidence secret pattern matches.
    This cannot happen through Finding (no raw field); it catches e.g. a file *named* like a token."""
    rule = leaked_rule(text)
    if rule is not None:
        raise RedactionError(
            f"Refusing to return this output: it matched the {rule!r} secret pattern. Scan results are redacted by "
            "construction, so the likely cause is a file or directory NAME that itself looks like a secret. "
            "Rename it or add it to .gitignore, then scan again. The matching text is not shown."
        )
    return text


def _key(f: Finding) -> tuple[int, str, int]:
    return (_SEV[f.severity], f.path, f.line)


def tree_report(res: TreeScan, max_findings: int) -> str:
    where = "git repository: .gitignore respected" if res.is_git else "not a git repository: .gitignore NOT applied"
    head = [
        f"scan_tree: {res.root}",
        f"Scanned {res.files_scanned} files ({where}; skipped {res.skipped_binary} binary, "
        f"{res.skipped_large} over 1 MB). {len(res.findings)} finding(s)"
        + (f", {res.suppressed} suppressed by .secretscan-ignore." if res.suppressed else "."),
    ]
    if not res.findings:
        return "\n".join(head + ["", "No secrets detected. Detection is pattern-based: absence of findings is not proof of absence."])
    rows = sorted(res.findings, key=_key)
    lines = [f"{f.severity.upper():<6} {f.id}  {f.rule:<26} {f.path}:{f.line}  {f.preview}" for f in rows[:max_findings]]
    if len(rows) > max_findings:
        lines.append(f"... {len(rows) - max_findings} more not shown (raise max_findings).")
    tail = [
        "",
        "Values are never shown. Next: explain_finding(<id>) for what it is and how to rotate it; "
        "scan_history(path) to see whether it (or others) also sit in git history; suggest_remediation(path) for the checklist.",
    ]
    return "\n".join(head + [""] + lines + tail)


def history_report(res: HistoryScan, max_findings: int) -> str:
    removed = [h for h in res.findings if not h.present]
    present = [h for h in res.findings if h.present]
    scope = f"{res.commits_scanned} commit(s)" + (" (limit reached: older commits were NOT scanned, raise max_commits)" if res.truncated else "")
    head = [
        f"scan_history: {res.root}",
        f"Scanned {scope}. {len(res.findings)} distinct secret(s) found: {len(removed)} removed from the "
        f"files but STILL IN HISTORY, {len(present)} still present in the newest scanned commit."
        + (f" {res.suppressed} suppressed by .secretscan-ignore." if res.suppressed else ""),
    ]
    if res.oversized_diffs:
        head.append(f"Note: {res.oversized_diffs} huge diff(s) were only partly scanned.")
    if not res.findings:
        return "\n".join(head + ["", "No secrets detected in the scanned history."])
    rows = sorted(res.findings, key=lambda h: (h.present, _key(h.finding)))
    lines = []
    for h in rows[:max_findings]:
        f = h.finding
        status = "PRESENT" if h.present else "REMOVED"
        added = f"added in {h.added_commit} ({h.added_date[:10]})" if h.added_commit else "added before the scanned window"
        gone = f", removed in {h.removed_commit} ({h.removed_date[:10]})" if h.removed_commit else ""
        lines.append(f"{status:<7} {f.severity.upper():<6} {f.id}  {f.rule:<26} {f.path}:{f.line}  {f.preview}\n"
                     f"        {added}{gone}")
    if len(rows) > max_findings:
        lines.append(f"... {len(rows) - max_findings} more not shown (raise max_findings).")
    tail = [
        "",
        "REMOVED does not mean safe: anyone who cloned or fetched while it was there still has it. Rotate the credential. "
        "Next: explain_finding(<id>), suggest_remediation(path).",
    ]
    return "\n".join(head + [""] + lines + tail)
