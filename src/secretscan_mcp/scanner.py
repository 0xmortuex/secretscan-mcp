"""Tree and history scanners, plus the .secretscan-ignore baseline."""

from __future__ import annotations

import fnmatch
import os
import re
from dataclasses import dataclass, field
from typing import Iterable

from . import gitutil
from .detect import Finding, scan_text

IGNORE_FILE = ".secretscan-ignore"
MAX_FILE_BYTES = 1_000_000
MAX_DIFF_LINES = 100_000  # per file per commit; bigger diffs are generated data

SKIP_DIRS = frozenset({
    ".git", "node_modules", "vendor", "bower_components", ".venv", "venv", "site-packages",
    "__pycache__", ".tox", ".mypy_cache", ".pytest_cache", ".ruff_cache", ".gradle", "Pods",
})
SKIP_NAMES = frozenset({
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "npm-shrinkwrap.json", "uv.lock",
    "poetry.lock", "Pipfile.lock", "Cargo.lock", "go.sum", "Gemfile.lock", "composer.lock",
    "packages.lock.json", "pubspec.lock", "bun.lock", IGNORE_FILE,
})
SKIP_GLOBS = (
    "*.min.js", "*.min.css", "*.map", "*.lock", "*.png", "*.jpg", "*.jpeg", "*.gif", "*.ico", "*.webp",
    "*.bmp", "*.svg", "*.pdf", "*.zip", "*.gz", "*.tgz", "*.bz2", "*.xz", "*.7z", "*.jar", "*.whl",
    "*.woff", "*.woff2", "*.ttf", "*.otf", "*.eot", "*.mp3", "*.mp4", "*.mov", "*.exe", "*.dll",
    "*.so", "*.dylib", "*.class", "*.pyc", "*.o", "*.a", "*.wasm", "*.bin",
)


def should_skip(relpath: str) -> bool:
    parts = relpath.replace("\\", "/").split("/")
    if any(p in SKIP_DIRS for p in parts[:-1]):
        return True
    name = parts[-1]
    return name in SKIP_NAMES or any(fnmatch.fnmatch(name.lower(), g) for g in SKIP_GLOBS)


# --- baseline / allowlist ---------------------------------------------------

_FP = re.compile(r"^(?:f-)?([0-9a-f]{16})$")


def load_ignore(directory: str) -> set[str]:
    """Fingerprints from <directory>/.secretscan-ignore. A bad line is an error,
    and the message never echoes the line (someone may have pasted a raw secret)."""
    path = os.path.join(directory, IGNORE_FILE)
    if not os.path.isfile(path):
        return set()
    out: set[str] = set()
    with open(path, encoding="utf-8") as fh:
        for n, raw in enumerate(fh, 1):
            token = raw.split("#", 1)[0].strip()
            if not token:
                continue
            m = _FP.match(token)
            if m is None:
                raise ValueError(
                    f"{path} line {n}: expected a 16-character hex fingerprint (as printed by "
                    f"scan_tree, e.g. f-0123456789abcdef), got {len(token)} characters that are not one. "
                    "The line is not shown in case it is a raw secret - remove it from the file."
                )
            out.add(m.group(1))
    return out


# --- tree -------------------------------------------------------------------


@dataclass
class TreeScan:
    root: str
    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    skipped_large: int = 0
    skipped_binary: int = 0
    suppressed: int = 0
    is_git: bool = False


def _walk(root: str) -> Iterable[str]:
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for f in sorted(filenames):
            yield os.path.relpath(os.path.join(dirpath, f), root).replace(os.sep, "/")


def check_dir(path: str) -> str:
    p = os.path.abspath(os.path.expanduser(path))
    if not os.path.exists(p):
        raise ValueError(f"path does not exist: {p}")
    if not os.path.isdir(p):
        raise ValueError(f"path is a file, not a directory: {p}. Pass the project (repository) directory.")
    return p


def scan_tree(path: str) -> TreeScan:
    root = check_dir(path)
    top = gitutil.toplevel(root)
    ignore = load_ignore(top or root)
    result = TreeScan(root=root, is_git=top is not None)
    if top is not None:
        # tracked + untracked-but-not-ignored: exactly what a `git add .` would pick up.
        rels: Iterable[str] = sorted(set(gitutil.ls_files(root, "--cached", "--others", "--exclude-standard")))
    else:
        rels = _walk(root)
    for rel in rels:
        if should_skip(rel):
            continue
        full = os.path.join(root, rel)
        if os.path.islink(full) or not os.path.isfile(full):
            continue  # never follow links out of the tree; submodule dirs show up as non-files
        if os.path.getsize(full) > MAX_FILE_BYTES:
            result.skipped_large += 1
            continue
        with open(full, "rb") as fh:
            data = fh.read()
        if b"\0" in data[:8192]:
            result.skipped_binary += 1
            continue
        result.files_scanned += 1
        for f in scan_text(data.decode("utf-8", "replace"), rel):
            if f.fingerprint in ignore:
                result.suppressed += 1
            else:
                result.findings.append(f)
    return result


# --- history ----------------------------------------------------------------


@dataclass
class HistoryFinding:
    finding: Finding  # location where it was first added, if that is inside the scanned window
    added_commit: str = ""
    added_date: str = ""
    removed_commit: str = ""
    removed_date: str = ""
    present: bool = False  # still in the newest scanned commit


@dataclass
class HistoryScan:
    root: str
    findings: list[HistoryFinding] = field(default_factory=list)
    commits_scanned: int = 0
    truncated: bool = False  # more commits exist than max_commits
    suppressed: int = 0
    oversized_diffs: int = 0


_HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


def _diff_path(line: str, prefix: str) -> str | None:
    p = line[4:].split("\t", 1)[0]
    if p == "/dev/null":
        return None
    return p[2:] if p.startswith(prefix) else p


def scan_history(path: str, max_commits: int = 500, all_refs: bool = False) -> HistoryScan:
    root = check_dir(path)
    top = gitutil.toplevel(root)
    if top is None:
        raise ValueError(f"{root} is not inside a git repository, so there is no history to scan. "
                         "Use scan_tree for plain directories.")
    if not gitutil.has_commits(root):
        raise ValueError(f"{root} is a git repository with no commits yet - nothing in history to scan.")
    if max_commits < 1:
        raise ValueError("max_commits must be at least 1")
    ignore = load_ignore(top)
    result = HistoryScan(root=root)
    state: dict[str, HistoryFinding] = {}
    suppressed: set[str] = set()

    commit = ("", "")
    commit_adds: dict[str, Finding] = {}
    commit_rems: dict[str, Finding] = {}

    cur_path: str | None = None
    minus_path: str | None = None
    adds: list[tuple[int, str]] = []
    rems: list[tuple[int, str]] = []
    oversize = False
    old_left = new_left = old_no = new_no = 0

    def flush_file() -> None:
        nonlocal adds, rems, oversize, cur_path, minus_path
        if cur_path and not should_skip(cur_path):
            for lines, store, removed in ((adds, commit_adds, False), (rems, commit_rems, True)):
                if lines:
                    text = "\n".join(t for _, t in lines)
                    for f in scan_text(text, cur_path, [n for n, _ in lines], commit[0][:12], removed):
                        store.setdefault(f.fingerprint, f)
        if oversize:
            result.oversized_diffs += 1
        adds, rems, oversize, cur_path, minus_path = [], [], False, None, None

    def flush_commit() -> None:
        sha, date = commit
        if not sha:
            return
        moved = commit_adds.keys() & commit_rems.keys()  # same secret on both sides: net no change
        for fp, f in commit_rems.items():
            if fp in moved:
                continue
            if fp in ignore:
                suppressed.add(fp)
                continue
            if fp not in state:
                state[fp] = HistoryFinding(f, removed_commit=sha[:12], removed_date=date)
        for fp, f in commit_adds.items():
            if fp in moved:
                continue
            if fp in ignore:
                suppressed.add(fp)
                continue
            hf = state.get(fp)
            if hf is None:
                hf = state[fp] = HistoryFinding(f, present=True)
            hf.finding = f
            hf.added_commit, hf.added_date = sha[:12], date
        commit_adds.clear()
        commit_rems.clear()

    for line in gitutil.stream_log(root, max_commits, all_refs):
        if line.startswith("\x01"):
            flush_file()
            flush_commit()
            sha, _, date = line[1:].partition(" ")
            commit = (sha, date)
            result.commits_scanned += 1
            old_left = new_left = 0
            continue
        if old_left > 0 or new_left > 0:  # inside a hunk: the counts, not the prefix, say where it ends
            c = line[:1]
            if c == "+":
                new_left -= 1
                if len(adds) < MAX_DIFF_LINES:
                    adds.append((new_no, line[1:]))
                else:
                    oversize = True
                new_no += 1
            elif c == "-":
                old_left -= 1
                if len(rems) < MAX_DIFF_LINES:
                    rems.append((old_no, line[1:]))
                else:
                    oversize = True
                old_no += 1
            elif c != "\\":
                old_left -= 1
                new_left -= 1
            continue
        if line.startswith("diff --git "):
            flush_file()
        elif line.startswith("--- "):
            minus_path = _diff_path(line, "a/")
        elif line.startswith("+++ "):
            cur_path = _diff_path(line, "b/") or minus_path
        elif line.startswith("@@"):
            m = _HUNK.match(line)
            if m:
                old_no, old_left = int(m.group(1)), int(m.group(2) if m.group(2) is not None else 1)
                new_no, new_left = int(m.group(3)), int(m.group(4) if m.group(4) is not None else 1)
    flush_file()
    flush_commit()

    result.findings = list(state.values())
    result.suppressed = len(suppressed)
    result.truncated = result.commits_scanned >= max_commits and _more_commits(root, max_commits, all_refs)
    return result


def _more_commits(root: str, max_commits: int, all_refs: bool) -> bool:
    args = ["rev-list", "--count"] + (["--all"] if all_refs else ["HEAD"])
    return int(gitutil.run(args, root).strip() or b"0") > max_commits
