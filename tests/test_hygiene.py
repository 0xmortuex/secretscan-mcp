"""check_gitignore against real repositories."""

import pytest
from conftest import commit_all, git, write

from secretscan_mcp.hygiene import check_gitignore, sensitive_by_name


def test_sensitive_names():
    for n in [".env", ".env.production", "a/b/id_rsa", "server.pem", "x.tfvars", "credentials.json",
              "home/.aws/credentials"]:
        assert sensitive_by_name(n), n
    for n in [".env.example", ".env.sample", "README.md", "id_rsa.example", "src/keys.py", "main.tf"]:
        assert not sensitive_by_name(n), n


def test_tracked_env_is_a_problem_even_when_ignored_later(repo):
    write(repo, ".env", "A=1\n")
    commit_all(repo, "oops")
    write(repo, ".gitignore", ".env\n")
    commit_all(repo, "ignore")
    out = check_gitignore(str(repo))
    assert "PROBLEM" in out and 'git rm --cached ".env"' in out
    assert "match a .gitignore rule" not in out  # not double-reported


def test_untracked_unignored_secret_file_is_a_warning(repo):
    write(repo, "a.py", "x=1\n")
    commit_all(repo, "i")
    write(repo, "private.key", "x\n")
    out = check_gitignore(str(repo))
    assert "WARNING" in out and "private.key" in out


def test_properly_ignored_env_is_ok_and_has_no_gap(repo):
    write(repo, ".gitignore", ".env\n.env.*\n*.pem\n*.key\nid_rsa\n!.env.example\n")
    write(repo, ".env", "A=1\n")
    write(repo, ".env.example", "A=\n")
    commit_all(repo, "i")
    out = check_gitignore(str(repo))
    assert "OK - " in out and "PROBLEM" not in out and "WARNING" not in out and "GAP" not in out
    assert ".env.example" not in out.split("OK -")[1]


def test_gap_when_nothing_is_ignored(repo):
    write(repo, "a.py", "x=1\n")
    commit_all(repo, "i")
    out = check_gitignore(str(repo))
    assert "GAP" in out and ".env" in out and "Suggested .gitignore lines" in out


def test_tracked_but_ignored_note(repo):
    write(repo, "debug.log", "x\n")
    commit_all(repo, "i")
    write(repo, ".gitignore", "*.log\n")
    out = check_gitignore(str(repo))
    assert "NOTE" in out and "debug.log" in out


def test_not_a_repo(tmp_path):
    with pytest.raises(ValueError, match="not inside a git repository"):
        check_gitignore(str(tmp_path))
    git(tmp_path, "init", "-q")
    assert "check_gitignore" in check_gitignore(str(tmp_path))
