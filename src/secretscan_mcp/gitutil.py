"""Thin wrapper over the real `git` binary. Argument lists only, never a shell.

Only read-only git subcommands are used (ls-files, log, check-ignore, rev-parse).
Config that can make git execute repository-controlled programs is switched off,
so scanning an untrusted clone cannot run its code.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from typing import Iterator

# core.fsmonitor can run a hook from the repo's own config; quotepath=false keeps
# non-ASCII file names readable instead of octal-escaped.
_SAFE = ["-c", "core.fsmonitor=false", "-c", "core.quotepath=false", "-c", "core.pager=cat"]


class GitError(ValueError):
    """A git failure with a message the agent can act on."""


def _git() -> str:
    exe = shutil.which("git")
    if exe is None:
        raise GitError("git was not found on PATH. Install git (https://git-scm.com) and restart the MCP client.")
    return exe


def _env() -> dict[str, str]:
    env = dict(os.environ)
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["GIT_OPTIONAL_LOCKS"] = "0"
    env["LC_ALL"] = "C"
    return env


def _fail(args: list[str], cwd: str, code: int, stderr: str) -> GitError:
    detail = stderr.strip() or "no error output"
    hint = ""
    if "dubious ownership" in detail:
        hint = f" Fix: run `git config --global --add safe.directory {cwd}` yourself, then retry."
    return GitError(f"`git {args[0]}` failed in {cwd} (exit {code}): {detail}.{hint}")


def run(args: list[str], cwd: str) -> bytes:
    proc = subprocess.run([_git(), *_SAFE, *args], cwd=cwd, capture_output=True, env=_env(), timeout=120)
    if proc.returncode != 0:
        raise _fail(args, cwd, proc.returncode, proc.stderr.decode("utf-8", "replace"))
    return proc.stdout


def toplevel(path: str) -> str | None:
    """Repository root containing `path`, or None if it is not inside a work tree."""
    proc = subprocess.run([_git(), *_SAFE, "rev-parse", "--show-toplevel"], cwd=path,
                          capture_output=True, env=_env(), timeout=30)
    if proc.returncode != 0:
        return None
    return os.path.normpath(proc.stdout.decode("utf-8", "replace").strip())


def ls_files(path: str, *flags: str) -> list[str]:
    out = run(["ls-files", "-z", *flags], path)
    return [p.decode("utf-8", "replace") for p in out.split(b"\0") if p]


def has_commits(path: str) -> bool:
    proc = subprocess.run([_git(), *_SAFE, "rev-parse", "--verify", "-q", "HEAD"], cwd=path,
                          capture_output=True, env=_env(), timeout=30)
    return proc.returncode == 0


def is_ignored(path: str, name: str) -> bool:
    """Would `name` be ignored if it existed (ignoring whether it is tracked)?"""
    proc = subprocess.run([_git(), *_SAFE, "check-ignore", "-q", "--no-index", "--", name], cwd=path,
                          capture_output=True, env=_env(), timeout=30)
    if proc.returncode in (0, 1):
        return proc.returncode == 0
    raise _fail(["check-ignore"], path, proc.returncode, proc.stderr.decode("utf-8", "replace"))


def stream_log(path: str, max_commits: int, all_refs: bool) -> Iterator[str]:
    """Yield `git log -p -U0` output line by line without holding it in memory.

    Each commit starts with a line that begins with \\x01 followed by "<sha> <iso date>".
    """
    args = [_git(), *_SAFE, "log", "-p", "-U0", "--no-color", "--no-ext-diff", "--no-textconv",
            "--no-renames", "--format=%x01%H %aI", f"--max-count={max_commits}"]
    if all_refs:
        args.append("--all")
    # stderr goes to a file, not a pipe: a full pipe would deadlock the stdout loop.
    with tempfile.TemporaryFile() as err:
        proc = subprocess.Popen(args, cwd=path, stdout=subprocess.PIPE, stderr=err, env=_env())
        assert proc.stdout is not None
        try:
            for raw in proc.stdout:
                yield raw.decode("utf-8", "replace").rstrip("\n").rstrip("\r")
            code = proc.wait()
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait()
        if code != 0:
            err.seek(0)
            raise _fail(["log"], path, code, err.read().decode("utf-8", "replace"))
