"""scan_history on real repositories: added-then-deleted secrets, attribution, edge cases."""

import pytest
from conftest import commit_all, fake_secrets, git, rnd, write

from secretscan_mcp.scanner import IGNORE_FILE, scan_history, scan_tree

S = fake_secrets()
GH = S["github-token"]


def test_secret_added_then_deleted_is_found_with_both_commits(repo):
    write(repo, "app.py", "x = 1\n")
    commit_all(repo, "base")
    write(repo, "app.py", f"x = 1\nTOKEN = '{GH}'\n")
    added = commit_all(repo, "oops")
    write(repo, "app.py", "x = 1\nimport os\nTOKEN = os.environ['T']\n")
    removed = commit_all(repo, "remove it")

    assert scan_tree(str(repo)).findings == []  # gone from the files...
    res = scan_history(str(repo))
    assert len(res.findings) == 1  # ...but not from history
    h = res.findings[0]
    assert h.finding.rule == "github-token" and not h.present
    assert h.added_commit == added[:12] and h.removed_commit == removed[:12]
    assert h.finding.path == "app.py" and h.finding.line == 2
    assert res.commits_scanned == 3 and not res.truncated


def test_secret_still_present_is_marked_present(repo):
    write(repo, "a.py", f"t='{GH}'\n")
    c = commit_all(repo, "add")
    write(repo, "b.py", "y = 2\n")
    commit_all(repo, "other")
    h = scan_history(str(repo)).findings[0]
    assert h.present and h.added_commit == c[:12] and h.removed_commit == ""


def test_file_deleted_wholesale(repo):
    write(repo, ".env", f"STRIPE={S['stripe-live-key']}\n")
    a = commit_all(repo, "env")
    git(repo, "rm", "-q", ".env")
    r = commit_all(repo, "rm env")
    h = scan_history(str(repo)).findings[0]
    assert (h.finding.path, h.finding.rule, h.added_commit, h.removed_commit) == (
        ".env", "stripe-live-key", a[:12], r[:12])


def test_move_between_files_in_one_commit_is_not_a_removal(repo):
    write(repo, "a.py", f"t='{GH}'\n")
    commit_all(repo, "add")
    git(repo, "mv", "a.py", "b.py")
    commit_all(repo, "rename")
    write(repo, "b.py", f"# moved\nt='{GH}'\n")
    commit_all(repo, "edit around it")
    res = scan_history(str(repo))
    assert len(res.findings) == 1 and res.findings[0].present


def test_multiline_private_key_in_history(repo):
    write(repo, "deploy/key.pem", S["private-key"] + "\n")
    a = commit_all(repo, "key")
    git(repo, "rm", "-q", "-r", "deploy")
    commit_all(repo, "rm key")
    h = scan_history(str(repo)).findings[0]
    assert h.finding.rule == "private-key" and not h.present and h.added_commit == a[:12]
    assert h.finding.path == "deploy/key.pem" and h.finding.line == 1


def test_added_line_that_looks_like_a_diff_header(repo):
    # a content line "++ x" shows up in the diff as "+++ x": hunk counts must keep the parser honest
    write(repo, "notes.txt", f"-- a\n++ b\n--- c\n+++ d\nt = '{GH}'\n")
    c = commit_all(repo, "tricky")
    h = scan_history(str(repo)).findings[0]
    assert h.finding.path == "notes.txt" and h.finding.line == 5 and h.added_commit == c[:12]


def test_file_names_with_spaces_and_unicode(repo):
    write(repo, "my config/clé secrète.txt", f"t='{GH}'\n")
    commit_all(repo, "odd names")
    assert scan_history(str(repo)).findings[0].finding.path == "my config/clé secrète.txt"


def test_max_commits_limits_and_reports_truncation(repo):
    write(repo, "a.py", f"t='{GH}'\n")
    commit_all(repo, "old leak")
    for i in range(4):
        write(repo, "n.txt", f"{i}\n")
        commit_all(repo, f"c{i}")
    res = scan_history(str(repo), max_commits=2)
    assert res.commits_scanned == 2 and res.truncated and res.findings == []
    full = scan_history(str(repo), max_commits=50)
    assert not full.truncated and len(full.findings) == 1


def test_all_branches_flag(repo):
    write(repo, "a.py", "x = 1\n")
    commit_all(repo, "base")
    git(repo, "checkout", "-q", "-b", "feature")
    write(repo, "leak.py", f"t='{GH}'\n")
    commit_all(repo, "leak on branch")
    git(repo, "checkout", "-q", "main")
    assert scan_history(str(repo)).findings == []
    assert len(scan_history(str(repo), all_refs=True).findings) == 1


def test_same_secret_in_many_commits_is_one_finding(repo):
    for i in range(3):
        write(repo, f"f{i}.py", f"t='{GH}'\n")
        commit_all(repo, f"c{i}")
    res = scan_history(str(repo))
    assert len(res.findings) == 1 and res.findings[0].added_commit != ""


def test_ignore_file_applies_to_history(repo):
    write(repo, "a.py", f"t='{GH}'\n")
    commit_all(repo, "leak")
    fp = scan_history(str(repo)).findings[0].finding.fingerprint
    write(repo, IGNORE_FILE, f"{fp}\n")
    commit_all(repo, "baseline")
    res = scan_history(str(repo))
    assert res.findings == [] and res.suppressed == 1


def test_lockfiles_in_history_are_skipped(repo):
    write(repo, "uv.lock", f'x="{GH}"\n')
    commit_all(repo, "lock")
    assert scan_history(str(repo)).findings == []


def test_binary_files_in_history_are_ignored(repo):
    (repo / "b.bin").write_bytes(b"\0\1" + GH.encode())
    commit_all(repo, "bin")
    assert scan_history(str(repo)).findings == []


def test_errors(tmp_path, repo):
    plain = tmp_path / "plain"
    plain.mkdir()
    with pytest.raises(ValueError, match="not inside a git repository"):
        scan_history(str(plain))
    with pytest.raises(ValueError, match="no commits yet"):
        scan_history(str(repo))
    write(repo, "a.py", "x=1\n")
    commit_all(repo, "c")
    with pytest.raises(ValueError, match="at least 1"):
        scan_history(str(repo), max_commits=0)


def test_url_credentials_in_history(repo):
    pw = rnd(20)
    write(repo, "settings.py", f'DB = "postgres://app:{pw}@db.internal.example.com/prod"\n')
    commit_all(repo, "db")
    write(repo, "settings.py", "DB = None\n")
    commit_all(repo, "fix")
    h = scan_history(str(repo)).findings[0]
    assert h.finding.rule == "url-credentials" and not h.present
    assert pw not in repr(h)
