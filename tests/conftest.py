"""Shared helpers: real git repos in temp dirs, and FAKE secrets assembled at test time.

No test file contains a literal token. Every fake is built from fragments plus seeded
random characters, so nothing here can be mistaken for a real credential by GitHub push
protection, and nothing real is ever used. The one literal is AWS's documented dummy
access key id, which AWS publishes for exactly this purpose.
"""

from __future__ import annotations

import base64
import json
import os
import random
import string
import subprocess
from pathlib import Path

import pytest

ALNUM = string.ascii_letters + string.digits
B64URL = ALNUM + "_-"
B64 = ALNUM + "+/"

AWS_EXAMPLE_ID = "AKIAIOSFODNN7EXAMPLE"  # documented by AWS as a dummy


def rnd(n: int, alphabet: str = ALNUM, seed: int = 1) -> str:
    """Deterministic 'random' text that always contains a digit and an upper-case letter."""
    r = random.Random(seed * 7919 + n)
    s = [r.choice(alphabet) for _ in range(n)]
    s[0], s[1] = r.choice(string.ascii_uppercase), r.choice(string.digits)
    return "".join(s)


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def fake_secrets() -> dict[str, str]:
    """rule id -> fake secret value that the rule must detect."""
    header = b64url(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload = b64url(json.dumps({"sub": "1234567890", "name": "Test User"}).encode())
    key_body = "\n".join(rnd(64, B64, seed=i) for i in range(3))
    return {
        "aws-access-key-id": AWS_EXAMPLE_ID,
        "github-token": "gh" + "p_" + rnd(36),
        "github-fine-grained-token": "github" + "_pat_" + rnd(22) + "_" + rnd(40, seed=2),
        "gitlab-token": "gl" + "pat-" + rnd(20, B64URL),
        "slack-token": "xo" + "xb-" + "123456789012-123456789012-" + rnd(24),
        "slack-webhook": "https://hooks." + "slack.com/services/T" + rnd(8).upper() + "/B" + rnd(8).upper() + "/" + rnd(24),
        "stripe-live-key": "sk" + "_live_" + rnd(28),
        "stripe-test-key": "sk" + "_test_" + rnd(28),
        "google-api-key": "AI" + "za" + rnd(35, B64URL),
        "anthropic-api-key": "sk-" + "ant-api03-" + rnd(90, B64URL),
        "openai-api-key": "sk-" + "proj-" + rnd(60, B64URL),
        "npm-token": "npm" + "_" + rnd(36),
        "pypi-token": "pypi-" + "AgEIcHlwaS5vcmc" + rnd(60, B64URL),
        "sendgrid-api-key": "SG" + "." + rnd(22, B64URL) + "." + rnd(43, B64URL),
        "jwt": header + "." + payload + "." + rnd(43, B64URL),
        "private-key": "-----BEGIN RSA " + "PRIVATE KEY-----\n" + key_body + "\n-----END RSA " + "PRIVATE KEY-----",
    }


def assignment_secrets() -> dict[str, tuple[str, str]]:
    """rule id -> (source line template with {} for the secret, secret)."""
    return {
        "aws-secret-access-key": ("aws_secret_access_key = {}", rnd(40, B64)),
        "url-credentials": ("DATABASE_URL=postgres://admin:{}@db.internal.example.com:5432/app", rnd(18)),
        "generic-secret": ('API_TOKEN = "{}"', rnd(32)),
    }


# --- git --------------------------------------------------------------------

_ENV = {
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_TERMINAL_PROMPT": "0",
    "GIT_AUTHOR_NAME": "Test Author",
    "GIT_AUTHOR_EMAIL": "author@example.invalid",
    "GIT_COMMITTER_NAME": "Test Author",
    "GIT_COMMITTER_EMAIL": "author@example.invalid",
}
_CFG = ["-c", "init.defaultBranch=main", "-c", "commit.gpgsign=false", "-c", "core.autocrlf=false",
        "-c", "core.safecrlf=false", "-c", "gc.auto=0"]


def git(repo: Path, *args: str) -> str:
    proc = subprocess.run(["git", *_CFG, *args], cwd=repo, capture_output=True, text=True,
                          env={**os.environ, **_ENV}, encoding="utf-8")
    assert proc.returncode == 0, f"git {args} failed: {proc.stderr}"
    return proc.stdout.strip()


def write(repo: Path, rel: str, text: str) -> None:
    p = repo / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)


def commit_all(repo: Path, message: str) -> str:
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", message)
    return git(repo, "rev-parse", "HEAD")


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    r = tmp_path / "proj"
    r.mkdir()
    git(r, "init", "-q")
    return r


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"
