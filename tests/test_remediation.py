"""Remediation text: provider coverage, ordering, and that nothing is executed or leaked."""

import pytest
from conftest import commit_all, fake_secrets, git, write

from secretscan_mcp.detect import RULES_BY_ID
from secretscan_mcp.remediation import NOT_UN_LEAKED, PROVIDERS, build_checklist, explain_rule
from secretscan_mcp.scanner import scan_history, scan_tree

S = fake_secrets()


@pytest.mark.parametrize("rule_id", sorted(RULES_BY_ID))
def test_every_rule_has_provider_specific_guidance(rule_id):
    assert RULES_BY_ID[rule_id].provider in PROVIDERS
    text = explain_rule(rule_id)
    assert "How to rotate" in text and "  1. " in text and "does not un-leak" in text


def test_provider_steps_are_specific():
    assert "iam update-access-key" in explain_rule("aws-access-key-id")
    assert "Revoke" in explain_rule("gitlab-token") or "revoke" in explain_rule("gitlab-token")
    assert "Roll key" in explain_rule("stripe-live-key")
    assert "history" in NOT_UN_LEAKED


def test_checklist_for_a_leak_in_history(repo):
    write(repo, ".env", f"T={S['github-token']}\n")
    commit_all(repo, "leak")
    git(repo, "rm", "-q", ".env")
    commit_all(repo, "rm")
    text = build_checklist(scan_tree(str(repo)), scan_history(str(repo)))
    assert text.index("1. ROTATE") < text.index("git filter-repo") < text.index("git push --force")
    assert 'git filter-repo --invert-paths --path .env' in text
    assert "bfg --delete-files .env" in text
    assert "never prints the value" in text
    assert S["github-token"] not in text


def test_checklist_quotes_paths_with_spaces(repo):
    write(repo, "my dir/.env", f"T={S['github-token']}\n")
    commit_all(repo, "leak")
    text = build_checklist(scan_tree(str(repo)), scan_history(str(repo)))
    assert '--path "my dir/.env"' in text


def test_clean_project_gets_hygiene_steps_only(repo):
    write(repo, "a.py", "x = 1\n")
    commit_all(repo, "c")
    text = build_checklist(scan_tree(str(repo)), scan_history(str(repo)))
    assert "No secrets were found" in text and "filter-repo" not in text
