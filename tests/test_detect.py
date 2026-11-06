"""Rule-level tests: detection, redaction, and a corpus of benign look-alikes."""

import dataclasses

import pytest
from conftest import B64, assignment_secrets, fake_secrets, rnd

from secretscan_mcp.detect import RULES_BY_ID, Finding, fingerprint, redact, scan_text, shannon

SECRETS = fake_secrets()


@pytest.mark.parametrize("rule_id", sorted(SECRETS))
def test_each_rule_detects_its_fake_secret(rule_id):
    secret = SECRETS[rule_id]
    text = f"some = 1\nvalue: {secret}\nother = 2\n" if rule_id != "private-key" else f"x = 1\n{secret}\ny = 2\n"
    hits = scan_text(text, "f.txt")
    assert rule_id in {h.rule for h in hits}, (rule_id, [h.rule for h in hits])
    hit = next(h for h in hits if h.rule == rule_id)
    assert hit.line == 2
    assert hit.path == "f.txt"


@pytest.mark.parametrize("rule_id", sorted(assignment_secrets()))
def test_assignment_rules(rule_id):
    template, secret = assignment_secrets()[rule_id]
    hits = scan_text(template.format(secret), ".env")
    assert [h.rule for h in hits] == [rule_id]


def test_every_rule_has_a_test():
    covered = set(SECRETS) | set(assignment_secrets())
    assert covered >= set(RULES_BY_ID), set(RULES_BY_ID) - covered


def test_finding_has_no_field_that_can_hold_a_raw_secret():
    names = {f.name for f in dataclasses.fields(Finding)}
    assert names == {"id", "fingerprint", "rule", "severity", "path", "line", "preview", "commit", "removed"}


@pytest.mark.parametrize("rule_id", sorted(SECRETS))
def test_findings_never_contain_the_value(rule_id):
    secret = SECRETS[rule_id]
    for h in scan_text(f"token = {secret}\n", "f.txt"):
        blob = repr(h) + str(dataclasses.asdict(h))
        assert secret not in blob
        assert secret[4:] not in blob
        assert len(h.preview) < 40


def test_redact_rules():
    assert redact("AKIAIOSFODNN7EXAMPLE") == "AKIA... (20 chars)"
    # short secrets reveal no characters at all
    assert redact("hunter2hunter2") == "**** (14 chars)"
    assert "hunter" not in redact("hunter2hunter2")


def test_fingerprint_is_stable_and_rule_scoped():
    assert fingerprint("a", "x") == fingerprint("a", "x")
    assert fingerprint("a", "x") != fingerprint("b", "x")
    assert len(fingerprint("a", "x")) == 16


def test_specific_rule_beats_generic_on_same_span():
    line = f"AWS_SECRET_ACCESS_KEY={rnd(40, B64)}\n"
    assert [h.rule for h in scan_text(line, "x")] == ["aws-secret-access-key"]
    line = f"github_token = {SECRETS['github-token']}\n"
    assert [h.rule for h in scan_text(line, "x")] == ["github-token"]


def test_entropy_values():
    assert shannon("aaaaaaaa") == 0
    assert shannon(rnd(40)) > 4.0
    assert shannon("changemechangeme") < 3.1


def test_line_numbers_follow_the_diff_mapping():
    secret = SECRETS["github-token"]
    hits = scan_text(f"a\n{secret}\n", "f", line_numbers=[40, 41], commit="abc", removed=True)
    assert hits[0].line == 41 and hits[0].commit == "abc" and hits[0].removed


# --- false positives --------------------------------------------------------

_HEX40 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
_HEX64 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
_BASE64_IMG = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg=="

BENIGN = [
    f'commit = "{_HEX40}"',
    f"sha256 = {_HEX64}",
    f"git checkout {_HEX40}",
    "id = 123e4567-e89b-12d3-a456-426614174000",
    'session_id: "9b2f0c1e-7d3a-4e5b-8c6d-1a2b3c4d5e6f"',
    'api_key = "123e4567-e89b-12d3-a456-426614174000"',
    f'<img src="data:image/png;base64,{_BASE64_IMG}">',
    "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore.",
    'password = os.environ["DB_PASSWORD"]',
    "password: str",
    "token = get_token()",
    "token: Optional[str] = None",
    "secret = process.env.APP_SECRET",
    "const apiKey = config.api.key;",
    'api_key = "your_api_key_here"',
    'SECRET_KEY = "changeme"',
    'password = "${DB_PASSWORD}"',
    "token: ${{ secrets.GITHUB_TOKEN }}",
    "api_key=<YOUR_KEY_HERE>",
    "token_length = 32",
    'password_field = "password_confirmation"',
    '"integrity": "sha512-Zq0r2PbH5kA3o7mQ1pYV9xk5HkJ0GZ0k8HcCq3N3m0tPz6y5p3m3dZ2nQk0N3o7mQ1pYV9xk5HkJ0GZ0k8Hc=="',
    'secret_manager_client_factory_name = "SecretManagerClientFactory"',
    "password = 'aaaaaaaaaaaa'",
    "password = '************'",
    'token = "0000000000000000"',
    "DATABASE_URL=postgres://user:password@localhost:5432/db",
    "url = https://github.com/0xmortuex/secretscan-mcp.git",
    "remote = git@github.com:0xmortuex/secretscan-mcp.git",
    "https://example.com/path?x=1&y=2",
    "color: #1a2b3c4d;",
    "version = 1.2.3-rc.1+build.5",
    'checksum_token = "d41d8cd98f00b204e9800998ecf8427e"',
    "csrf_token = 'a8f5f167f44f4964e6c998dee827110c'",
    "ssh-rsa-key-name = my-deploy-key",
    "def verify_password(password, hashed_password):",
    "return jwt.decode(token, secret, algorithms=['HS256'])",
    "Authorization: Bearer ${TOKEN}",
    "sk-learn-is-not-a-key",
    "AKIA is the prefix of AWS access key ids",
    "-----BEGIN CERTIFICATE-----",
    "password: ''",
]


@pytest.mark.parametrize("line", BENIGN)
def test_benign_lookalikes_are_not_flagged(line):
    hits = scan_text(line + "\n", "doc.md")
    assert hits == [], [(h.rule, h.preview) for h in hits]


def test_public_certificate_block_is_not_a_private_key():
    pem = "-----BEGIN CERTIFICATE-----\n" + "\n".join(rnd(64, B64, seed=i) for i in range(4)) + "\n-----END CERTIFICATE-----\n"
    assert scan_text(pem, "ca.pem") == []


def test_garbage_jwt_lookalike_is_rejected():
    fake = "eyJ" + "zzzzzzzzzz" + ".eyJ" + "zzzzzzzzzz" + ".abcdefghij"  # header does not decode to JSON
    assert scan_text(fake, "x") == []


def test_huge_lines_are_skipped():
    secret = SECRETS["github-token"]
    assert scan_text(secret + " " + "x" * 20_000, "bundle.js") == []


def test_text_whose_lowercase_changes_length_still_finds_secrets():
    # 'I' with a dot above lowercases to two code points; line mapping must not drift
    secret = SECRETS["github-token"]
    text = "İİİ title\n" * 3 + f"t = '{secret}'\n"
    hits = scan_text(text, "x")
    assert [(h.rule, h.line) for h in hits] == [("github-token", 4)]
