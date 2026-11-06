"""check_gitignore: are secret-bearing files ignored and untracked?"""

from __future__ import annotations

import fnmatch
import os

from . import gitutil
from .scanner import check_dir

_EXACT = frozenset({
    ".env", ".npmrc", ".pypirc", ".netrc", ".htpasswd", "credentials", "credentials.json", "secrets.json",
    "secrets.yml", "secrets.yaml", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "terraform.tfstate",
    "terraform.tfstate.backup", "service-account.json",
})
_GLOBS = ("*.pem", "*.key", "*.p12", "*.pfx", "*.jks", "*.keystore", "*.ppk", "*.tfvars",
          "service-account*.json", "*-credentials.json")
_TEMPLATE_WORDS = ("example", "sample", "template", "dist", "defaults", "default")
# Names we ask git "would you ignore this?" for, even if no such file exists yet.
_PROBES = (".env", ".env.local", ".env.production", "server.pem", "private.key", "id_rsa")


def sensitive_by_name(relpath: str) -> bool:
    p = relpath.replace("\\", "/")
    name = os.path.basename(p).lower()
    if p.lower().endswith(".aws/credentials"):
        return True
    if name.startswith(".env."):
        return not any(w in name for w in _TEMPLATE_WORDS)
    if name.endswith(tuple("." + w for w in _TEMPLATE_WORDS)):
        return False
    return name in _EXACT or any(fnmatch.fnmatch(name, g) for g in _GLOBS)


def _q(p: str) -> str:
    return f'"{p}"'


def check_gitignore(path: str) -> str:
    root = check_dir(path)
    if gitutil.toplevel(root) is None:
        raise ValueError(f"{root} is not inside a git repository, so there is no .gitignore to check.")
    tracked = gitutil.ls_files(root, "--cached")
    untracked = gitutil.ls_files(root, "--others", "--exclude-standard")
    ignored_present = gitutil.ls_files(root, "--others", "--ignored", "--exclude-standard")
    tracked_ignored = gitutil.ls_files(root, "--cached", "--ignored", "--exclude-standard")

    bad_tracked = sorted(p for p in tracked if sensitive_by_name(p))
    bad_untracked = sorted(p for p in untracked if sensitive_by_name(p))
    good = sorted(p for p in ignored_present if sensitive_by_name(p))
    unprotected = [n for n in _PROBES if not gitutil.is_ignored(root, n)]

    out: list[str] = [f"check_gitignore: {root}", ""]
    problems = 0

    if bad_tracked:
        problems += len(bad_tracked)
        out.append("PROBLEM - secret-looking files that git TRACKS (being in .gitignore does not help once tracked):")
        out += [f"  {p}" for p in bad_tracked]
        out.append("  Stop tracking (keeps the local file):  " + "; ".join(f"git rm --cached {_q(p)}" for p in bad_tracked[:5]))
        out.append("  If they ever held real values those values are in history: run scan_history, rotate, see suggest_remediation.")
        out.append("")
    if bad_untracked:
        problems += len(bad_untracked)
        out.append("WARNING - secret-looking files that are untracked but NOT ignored (the next `git add .` commits them):")
        out += [f"  {p}" for p in bad_untracked]
        out.append("  Add them (or a pattern) to .gitignore now.")
        out.append("")
    other = sorted(set(tracked_ignored) - set(bad_tracked))
    if other:
        out.append(f"NOTE - {len(other)} tracked file(s) match a .gitignore rule, so the rule has no effect on them:")
        out += [f"  {p}" for p in other[:30]]
        if len(other) > 30:
            out.append(f"  ... and {len(other) - 30} more")
        out.append("")
    if unprotected:
        out.append("GAP - these names are not covered by any ignore rule, so a file created with that name would be committable:")
        out.append("  " + ", ".join(unprotected))
        lines = [n for n in (".env", ".env.*") if ".env" in unprotected or ".env.local" in unprotected]
        extra = [g for n, g in (("server.pem", "*.pem"), ("private.key", "*.key"), ("id_rsa", "id_rsa")) if n in unprotected]
        out.append("  Suggested .gitignore lines:  " + "   ".join(lines + extra))
        out.append("  (keep a committed .env.example with fake values:  !.env.example)")
        out.append("")
    if good:
        out.append("OK - secret-looking files present locally and correctly ignored:")
        out += [f"  {p}" for p in good]
        out.append("")
    if not (bad_tracked or bad_untracked or other or unprotected or good):
        out.append("No secret-looking files found and the common secret file names are all ignored.")
    elif problems == 0 and not unprotected:
        out.append("No problems found.")
    out.append("This check looks at file names only; use scan_tree to look inside files.")
    return "\n".join(out).rstrip()
