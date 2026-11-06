"""Detection: regex rules, entropy, false-positive filters.

Redaction by construction: the only place a raw secret value exists is inside
`scan_text`, in a local variable, for the few microseconds it takes to compute
a fingerprint and a preview. `Finding` has no field that could hold it.
"""

from __future__ import annotations

import base64
import hashlib
import json
import math
import re
from collections import Counter
from dataclasses import dataclass
from typing import Callable, Iterator, Optional

# Lines longer than this are minified bundles / data blobs, not hand-written config.
MAX_LINE = 10_000


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    provider: str  # key into remediation.PROVIDERS
    severity: str  # high | medium | low
    pattern: "re.Pattern[str]"
    group: int = 0  # which regex group is the secret
    validator: Optional[Callable[["re.Match[str]", str], bool]] = None
    needs: tuple[str, ...] = ()  # cheap prefilter: skip the regex unless one of these (lower-case) is in the line


@dataclass(frozen=True)
class Finding:
    """One redacted finding. There is deliberately no field for the raw value."""

    id: str  # "f-" + fingerprint
    fingerprint: str  # 16 hex chars of a domain-separated SHA-256; goes in .secretscan-ignore
    rule: str
    severity: str
    path: str
    line: int
    preview: str  # first 4 chars (long secrets only) + length, e.g. "AKIA... (20 chars)"
    commit: str = ""  # history findings only: commit that touched it
    removed: bool = False  # history findings only: this was a deleted line


def shannon(s: str) -> float:
    """Shannon entropy in bits per character."""
    if not s:
        return 0.0
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


def fingerprint(rule_id: str, secret: str) -> str:
    h = hashlib.sha256(f"secretscan-v1\0{rule_id}\0{secret}".encode("utf-8", "replace"))
    return h.hexdigest()[:16]


def redact(secret: str) -> str:
    """Never the whole value. Only secrets of 16+ chars show a 4-char prefix,
    which for provider tokens is the non-secret type marker (AKIA, ghp_, xoxb)."""
    if len(secret) >= 16:
        return f"{secret[:4]}... ({len(secret)} chars)"
    return f"**** ({len(secret)} chars)"


# --- false-positive filters -------------------------------------------------

_PLACEHOLDER_WORDS = (
    "example", "placeholder", "changeme", "change_me", "change-me", "yourpassword",
    "your_", "your-", "<your", "xxxx", "****", "....", "dummy", "sample", "redacted",
    "notasecret", "not_a_secret", "fixme", "todo", "insert", "replace", "secret_here",
    "password123", "lorem",
)
_REFERENCE_PREFIXES = ("$", "${", "%", "{{", "<", "@", "os.environ", "getenv", "process.env", "env(")
_DOTTED_IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+$")
_UUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_NOT_SECRET_KEYS = re.compile(
    r"hash|digest|checksum|sha\d*|md5|integrity|signature_|uuid|guid|etag|fingerprint|"
    r"_id$|^id$|public|csrf|nonce|salt|_url$|_path$|_file$|_name$|_type$|_header$|_prefix$|_field$|_label$",
    re.I,
)
_PASSWORDISH = re.compile(r"pass|pwd", re.I)


def looks_like_placeholder(value: str) -> bool:
    v = value.lower()
    if any(w in v for w in _PLACEHOLDER_WORDS):
        return True
    if v.startswith(tuple(p.lower() for p in _REFERENCE_PREFIXES)):
        return True
    if len(set(v)) <= 3:  # "aaaaaaaa", "00000000", "********"
        return True
    return False


def _classes(value: str) -> int:
    return sum(
        1
        for ok in (
            any(c.islower() for c in value),
            any(c.isupper() for c in value),
            any(c.isdigit() for c in value),
            any(not c.isalnum() for c in value),
        )
        if ok
    )


def _generic_ok(m: "re.Match[str]", line: str) -> bool:
    key, value = m.group("key"), m.group("val")
    if _NOT_SECRET_KEYS.search(key):
        return False
    if _UUID.match(value) or _DOTTED_IDENT.match(value) or looks_like_placeholder(value):
        return False
    if any(ch in value for ch in "()[]{}<>|\\"):
        return False  # a call, an index, a template, or a type annotation
    if not any(c.isdigit() for c in value):
        return False  # identifiers and words; real random secrets almost always carry a digit
    if _classes(value) < 2:
        return False
    if _PASSWORDISH.search(key):
        return len(value) >= 8 and shannon(value) >= 3.0
    return len(value) >= 16 and shannon(value) >= 3.5


def _jwt_ok(m: "re.Match[str]", line: str) -> bool:
    header = m.group(0).split(".")[0]
    try:
        raw = base64.urlsafe_b64decode(header + "=" * (-len(header) % 4))
        obj = json.loads(raw)
    except ValueError:
        return False
    return isinstance(obj, dict) and ("alg" in obj or "typ" in obj)


def _url_cred_ok(m: "re.Match[str]", line: str) -> bool:
    user, pw = m.group("user"), m.group("pw")
    if pw.lower() == user.lower() or looks_like_placeholder(pw):
        return False
    if pw.lower() in {"password", "pass", "passwd", "pwd", "secret", "user", "username", "token"}:
        return False
    return True


def _entropy_at_least(threshold: float) -> Callable[["re.Match[str]", str], bool]:
    def check(m: "re.Match[str]", line: str) -> bool:
        return shannon(m.group(m.lastindex or 0)) >= threshold

    return check


def _c(p: str, flags: int = 0) -> "re.Pattern[str]":
    return re.compile(p, flags)


RULES: tuple[Rule, ...] = (
    Rule("aws-access-key-id", "AWS access key ID", "aws", "high",
         _c(r"\b(?:AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16}\b"), needs=("akia","asia","abia","acca")),
    Rule("aws-secret-access-key", "AWS secret access key", "aws", "high",
         _c(r"(?i)\baws_?secret_?(?:access_?)?key\b[\"']?\s*[:=]\s*[\"']?([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])"),
         1, _entropy_at_least(3.5), ("aws",)),
    Rule("github-token", "GitHub token", "github", "high",
         _c(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,255}\b"), needs=("ghp_","gho_","ghu_","ghs_","ghr_")),
    Rule("github-fine-grained-token", "GitHub fine-grained personal access token", "github", "high",
         _c(r"\bgithub_pat_[A-Za-z0-9_]{22,255}\b"), needs=("github_pat_",)),
    Rule("gitlab-token", "GitLab personal access token", "gitlab", "high",
         _c(r"\bglpat-[A-Za-z0-9_\-]{20}\b"), needs=("glpat-",)),
    Rule("slack-token", "Slack token", "slack", "high",
         _c(r"\bxox[abprs]-[A-Za-z0-9\-]{10,}\b"), needs=("xox",)),
    Rule("slack-webhook", "Slack incoming webhook URL", "slack", "medium",
         _c(r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]{20,}"), needs=("hooks.slack.com",)),
    Rule("stripe-live-key", "Stripe live secret or restricted key", "stripe", "high",
         _c(r"\b[sr]k_live_[A-Za-z0-9]{16,}\b"), needs=("_live_",)),
    Rule("stripe-test-key", "Stripe test-mode secret key", "stripe", "low",
         _c(r"\b[sr]k_test_[A-Za-z0-9]{16,}\b"), needs=("_test_",)),
    Rule("google-api-key", "Google API key", "google", "high",
         _c(r"\bAIza[0-9A-Za-z_\-]{35}\b"), needs=("aiza",)),
    Rule("anthropic-api-key", "Anthropic API key", "anthropic", "high",
         _c(r"\bsk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_\-]{40,}\b"), needs=("sk-ant-",)),
    Rule("openai-api-key", "OpenAI API key", "openai", "high",
         _c(r"\bsk-(?:(?:proj|svcacct|admin)-[A-Za-z0-9_\-]{40,}|[A-Za-z0-9]{48})\b"),
         0, _entropy_at_least(3.5), needs=("sk-",)),
    Rule("npm-token", "npm access token", "npm", "high",
         _c(r"\bnpm_[A-Za-z0-9]{36}\b"), needs=("npm_",)),
    Rule("pypi-token", "PyPI API token", "pypi", "high",
         _c(r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,}\b"), needs=("pypi-",)),
    Rule("sendgrid-api-key", "SendGrid API key", "sendgrid", "high",
         _c(r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b"), needs=("sg.",)),
    Rule("jwt", "JSON Web Token", "jwt", "medium",
         _c(r"\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}"), 0, _jwt_ok, needs=("eyj",)),
    Rule("url-credentials", "Password embedded in a URL", "password", "medium",
         _c(r"\b[a-zA-Z][a-zA-Z0-9+.\-]{1,15}://(?P<user>[^\s:/@'\"<>]{1,64}):(?P<pw>[^\s/@'\"<>]{3,128})@[^\s/'\"<>]+"),
         0, _url_cred_ok, ("://",)),
    Rule("generic-secret", "Hard-coded secret in an assignment", "generic", "medium",
         _c(r"(?i)(?P<key>[A-Za-z0-9_.\-]*(?:secret|token|passw(?:or)?d|passwd|pwd|api[_\-]?key|apikey"
            r"|access[_\-]?key|auth[_\-]?key|private[_\-]?key|credential)[A-Za-z0-9_.\-]*)[\"']?\s*"
            r"(?::=|=|:)\s*[\"']?(?P<val>[^\s\"'`,;#]{8,200})"),
         0, _generic_ok, ("secret", "token", "pass", "pwd", "key", "credential")),
)

# Multi-line: matched against the whole text, not line by line.
_PRIVATE_KEY = re.compile(
    r"-----BEGIN (?P<kind>(?:[A-Z0-9]+ )*)PRIVATE KEY(?: BLOCK)?-----"
    r"(?P<body>[A-Za-z0-9+/=:,.\s\-]{40,}?)"
    r"-----END (?P=kind)PRIVATE KEY(?: BLOCK)?-----"
)

_SCREEN = re.compile("|".join(sorted({re.escape(n) for r in RULES for n in r.needs})))

RULES_BY_ID: dict[str, Rule] = {r.id: r for r in RULES}
RULES_BY_ID["private-key"] = Rule("private-key", "Private key block", "private-key", "high", _PRIVATE_KEY)

# Which rule wins when two hit the same place. Generic never beats a specific rule.
_GENERIC = "generic-secret"


def _secret_of(rule: Rule, m: "re.Match[str]") -> tuple[str, int, int]:
    if rule.id == "url-credentials":
        return m.group("pw"), m.start("pw"), m.end("pw")
    if rule.id == _GENERIC:
        return m.group("val"), m.start("val"), m.end("val")
    return m.group(rule.group), m.start(rule.group), m.end(rule.group)


def _line_hits(line: str) -> Iterator[tuple[Rule, str, int, int]]:
    lower = line.lower()
    for rule in RULES:
        if rule.needs and not any(n in lower for n in rule.needs):
            continue
        for m in rule.pattern.finditer(line):
            if rule.validator is not None and not rule.validator(m, line):
                continue
            secret, s, e = _secret_of(rule, m)
            yield rule, secret, s, e


def _candidate_lines(text: str) -> list[int]:
    """Indices of the lines containing any rule's literal hint, found in one pass over the whole text."""
    low = text.lower()  # the hints are lower-case; matching without re.I is several times faster
    if len(low) != len(text):  # a few Unicode letters change length when lowered: offsets would drift
        return list(range(text.count(chr(10)) + 1))
    out: list[int] = []
    last = ln = 0
    prev = -1
    for m in _SCREEN.finditer(low):
        ln += text.count(chr(10), last, m.start())
        last = m.start()
        if ln != prev:
            out.append(ln)
            prev = ln
    return out


def scan_text(text: str, path: str, line_numbers: Optional[list[int]] = None,
              commit: str = "", removed: bool = False) -> list[Finding]:
    """Scan `text`; return redacted findings. `line_numbers[i]` is the real line number
    of text line i (used for diff hunks); default is 1-based position."""
    hits: list[Finding] = []
    lines = text.split("\n")

    def lineno(i: int) -> int:
        return line_numbers[i] if line_numbers is not None else i + 1

    def add(rule: Rule, secret: str, i: int) -> None:
        fp = fingerprint(rule.id, secret)
        hits.append(Finding(f"f-{fp}", fp, rule.id, rule.severity, path, lineno(i),
                            redact(secret), commit, removed))

    for i in _candidate_lines(text):
        line = lines[i]
        if len(line) > MAX_LINE or len(line) < 8:
            continue
        spans: list[tuple[int, int]] = []
        found = list(_line_hits(line))
        for rule, secret, s, e in found:
            if rule.id != _GENERIC:
                spans.append((s, e))
                add(rule, secret, i)
        for rule, secret, s, e in found:
            if rule.id == _GENERIC and not any(s < b and a < e for a, b in spans):
                add(rule, secret, i)

    if "PRIVATE KEY" in text:
        for m in _PRIVATE_KEY.finditer(text):
            line_idx = text.count("\n", 0, m.start())
            add(RULES_BY_ID["private-key"], m.group(0), line_idx)
    return hits


def rule_ids() -> list[str]:
    return sorted(RULES_BY_ID)


def leaked_rule(text: str) -> Optional[str]:
    """Id of the first high-confidence (non-generic) rule that matches `text`, else None.
    Used as a last line of defence on tool output: redacted previews never match."""
    for line in text.split("\n"):
        if len(line) > MAX_LINE or len(line) < 8 or not _SCREEN.search(line):
            continue
        for rule, _secret, _s, _e in _line_hits(line):
            if rule.id != _GENERIC:
                return rule.id
    if "PRIVATE KEY" in text and _PRIVATE_KEY.search(text):
        return "private-key"
    return None
