"""scan_tree and the .secretscan-ignore baseline, on real git repos and real directories."""

import os

import pytest
from conftest import commit_all, fake_secrets, write

from secretscan_mcp.scanner import IGNORE_FILE, load_ignore, scan_tree, should_skip

S = fake_secrets()
GH = S["github-token"]


def test_finds_planted_secrets_in_a_real_repo(repo):
    write(repo, "src/app.py", f"import os\nKEY = '{GH}'\n")
    write(repo, "config/.env", f"AWS_ACCESS_KEY_ID={S['aws-access-key-id']}\n")
    write(repo, "README.md", "hello\n")
    commit_all(repo, "init")
    res = scan_tree(str(repo))
    got = {(f.path, f.rule, f.line) for f in res.findings}
    assert ("src/app.py", "github-token", 2) in got
    assert ("config/.env", "aws-access-key-id", 1) in got
    assert res.is_git and res.files_scanned == 3


def test_untracked_files_are_scanned_but_gitignored_ones_are_not(repo):
    write(repo, ".gitignore", ".env\nbuild/\n")
    write(repo, ".env", f"TOKEN={GH}\n")
    write(repo, "build/out.js", f"var t='{GH}'\n")
    commit_all(repo, "init")
    write(repo, "later_untracked.py", f"t = '{GH}'\n")
    paths = {f.path for f in scan_tree(str(repo)).findings}
    assert paths == {"later_untracked.py"}


def test_skips_lockfiles_vendored_binary_and_big_files(repo):
    write(repo, "uv.lock", f'token = "{GH}"\n')
    write(repo, "package-lock.json", f'{{"x": "{GH}"}}\n')
    write(repo, "node_modules/pkg/index.js", f"var t='{GH}'\n")
    write(repo, "vendor/lib.py", f"t='{GH}'\n")
    write(repo, "app.min.js", f"t='{GH}'\n")
    (repo / "blob.dat").write_bytes(b"\0\1\2" + GH.encode())
    write(repo, "big.txt", ("x" * 99 + "\n") * 11_000 + GH + "\n")
    write(repo, "real.py", f"t='{GH}'\n")
    commit_all(repo, "init")
    res = scan_tree(str(repo))
    assert [f.path for f in res.findings] == ["real.py"]
    assert res.skipped_binary == 1 and res.skipped_large == 1


def test_plain_directory_without_git(tmp_path):
    d = tmp_path / "plain"
    write(d, "a/b.py", f"t='{GH}'\n")
    write(d, "node_modules/x.js", f"t='{GH}'\n")
    res = scan_tree(str(d))
    assert not res.is_git
    assert [f.path for f in res.findings] == ["a/b.py"]


def test_subdirectory_of_a_repo(repo):
    write(repo, "a/x.py", f"t='{GH}'\n")
    write(repo, "b/y.py", f"t='{GH}'\n")
    commit_all(repo, "init")
    res = scan_tree(str(repo / "a"))
    assert [f.path for f in res.findings] == ["x.py"]


def test_symlinks_are_not_followed(repo, tmp_path):
    outside = tmp_path / "outside.txt"
    outside.write_text(f"t='{GH}'\n", encoding="utf-8")
    try:
        os.symlink(outside, repo / "link.txt")
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not available")
    write(repo, "ok.py", "x = 1\n")
    assert scan_tree(str(repo)).findings == []


def test_ignore_file_suppresses_by_fingerprint_not_value(repo):
    write(repo, "a.py", f"t='{GH}'\n")
    write(repo, "b.py", f"t='{S['stripe-live-key']}'\n")
    commit_all(repo, "init")
    before = scan_tree(str(repo)).findings
    assert len(before) == 2
    fp = next(f.fingerprint for f in before if f.path == "a.py")
    write(repo, IGNORE_FILE, f"# accepted\nf-{fp}  # old test token\n\n")
    res = scan_tree(str(repo))
    assert [f.path for f in res.findings] == ["b.py"]
    assert res.suppressed == 1
    assert GH not in (repo / IGNORE_FILE).read_text(encoding="utf-8")


def test_a_raw_secret_pasted_into_the_ignore_file_is_an_error_that_does_not_echo_it(repo):
    write(repo, IGNORE_FILE, f"{GH}\n")
    with pytest.raises(ValueError) as e:
        load_ignore(str(repo))
    assert GH not in str(e.value) and GH[4:] not in str(e.value)
    assert "line 1" in str(e.value)


def test_errors_are_actionable(tmp_path):
    with pytest.raises(ValueError, match="does not exist"):
        scan_tree(str(tmp_path / "nope"))
    f = tmp_path / "file.txt"
    f.write_text("x", encoding="utf-8")
    with pytest.raises(ValueError, match="not a directory"):
        scan_tree(str(f))


def test_should_skip():
    assert should_skip("a/node_modules/b.js") and should_skip("Cargo.lock") and should_skip("img/a.PNG")
    assert not should_skip("src/main.py") and not should_skip(".env")


def test_clean_repo_has_no_findings(repo):
    write(repo, "a.py", "print('hi')\n")
    commit_all(repo, "i")
    assert scan_tree(str(repo)).findings == []
