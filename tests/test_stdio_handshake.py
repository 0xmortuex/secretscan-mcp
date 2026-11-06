"""MCP stdio test: launches the real server as a subprocess, drives every tool over MCP, and
asserts the central safety claim: no raw secret value ever appears in any tool output or error."""

import re
import sys
from pathlib import Path

import pytest
from conftest import assignment_secrets, commit_all, fake_secrets, git, write

pytest.importorskip("mcp")

from mcp import ClientSession  # noqa: E402
from mcp.client.stdio import StdioServerParameters, stdio_client  # noqa: E402

EXPECTED_TOOLS = {
    "scan_tree", "scan_history", "check_gitignore", "explain_finding", "suggest_remediation", "make_baseline",
}

PARAMS = StdioServerParameters(command=sys.executable, args=["-m", "secretscan_mcp"])


def all_planted() -> list[str]:
    values = list(fake_secrets().values()) + [s for _, s in assignment_secrets().values()]
    return values


def assert_no_secret(text: str) -> None:
    for secret in all_planted():
        assert secret not in text
        # sliding 16-char windows: catches partial leaks, not just the whole value
        for i in range(0, len(secret) - 15):
            assert secret[i:i + 16] not in text, f"leaked a slice of a {len(secret)}-char secret"


def planted_repo(root: Path) -> Path:
    r = root / "leaky project"  # a space in the path, on purpose
    r.mkdir()
    git(r, "init", "-q")
    s = fake_secrets()
    write(r, "app/settings.py", f"import os\nGITHUB = '{s['github-token']}'\nOPENAI = '{s['openai-api-key']}'\n")
    write(r, "infra/deploy.pem", s["private-key"] + "\n")
    for name, (tmpl, secret) in assignment_secrets().items():
        write(r, f"cfg/{name}.env", tmpl.format(secret) + "\n")
    write(r, ".env", f"AWS_ACCESS_KEY_ID={s['aws-access-key-id']}\nSTRIPE={s['stripe-live-key']}\n")
    write(r, "docs/readme.md", "Lorem ipsum. sha256 = " + "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n")
    commit_all(r, "initial, with mistakes")
    write(r, "old.py", f"TOKEN = '{s['slack-token']}'\n")
    commit_all(r, "add slack token")
    git(r, "rm", "-q", "old.py")
    commit_all(r, "remove slack token")
    return r


async def call(session: ClientSession, name: str, args: dict, outputs: list[str]):
    res = await session.call_tool(name, args)
    text = "\n".join(c.text for c in res.content if hasattr(c, "text"))
    outputs.append(text)
    return res, text


@pytest.mark.anyio
async def test_tool_list_and_annotations():
    async with stdio_client(PARAMS) as (read, write_), ClientSession(read, write_) as session:
        init = await session.initialize()
        assert init.server_info.name == "secretscan"
        tools = (await session.list_tools()).tools
        assert {t.name for t in tools} == EXPECTED_TOOLS
        for t in tools:
            assert t.annotations is not None and t.annotations.read_only_hint is True
            assert t.description and len(t.description) > 80


@pytest.mark.anyio
async def test_full_session_never_leaks_a_raw_secret(tmp_path):
    repo = planted_repo(tmp_path)
    outputs: list[str] = []
    async with stdio_client(PARAMS) as (read, write_), ClientSession(read, write_) as session:
        await session.initialize()

        res, tree = await call(session, "scan_tree", {"path": str(repo)}, outputs)
        assert not res.is_error
        for rule in ["github-token", "openai-api-key", "private-key", "aws-access-key-id", "stripe-live-key",
                     "url-credentials", "generic-secret", "aws-secret-access-key"]:
            assert rule in tree, rule
        assert "AKIA... (20 chars)" in tree and "app/settings.py:2" in tree
        assert "sha256" not in tree  # the benign hash was not flagged

        res, hist = await call(session, "scan_history", {"path": str(repo)}, outputs)
        assert not res.is_error and "slack-token" in hist and "REMOVED" in hist and "STILL IN HISTORY" in hist

        res, ign = await call(session, "check_gitignore", {"path": str(repo)}, outputs)
        assert "PROBLEM" in ign and "git rm --cached" in ign

        ids = re.findall(r"f-[0-9a-f]{16}", tree + hist)
        assert ids
        for fid in ids[:8]:
            res, ex = await call(session, "explain_finding", {"id": fid}, outputs)
            assert not res.is_error and "How to rotate" in ex and "does not un-leak" in ex
        res, ex = await call(session, "explain_finding", {"id": "aws-access-key-id"}, outputs)
        assert "IAM" in ex

        res, rem = await call(session, "suggest_remediation", {"path": str(repo)}, outputs)
        assert not res.is_error and rem.index("1. ROTATE") < rem.index("filter-repo")
        assert "git filter-repo --invert-paths" in rem and "bfg" in rem and "replacements.txt" in rem

        res, base = await call(session, "make_baseline", {"path": str(repo), "include_history": True}, outputs)
        assert not res.is_error and ".secretscan-ignore" in base

        # apply the baseline the way a human would, then everything is suppressed
        lines = [ln for ln in base.splitlines() if re.match(r"^[0-9a-f]{16}\s", ln)]
        assert lines
        write(repo, ".secretscan-ignore", "\n".join(lines) + "\n")
        res, again = await call(session, "scan_tree", {"path": str(repo)}, outputs)
        assert "0 finding(s)" in again and "suppressed" in again
        res, again_h = await call(session, "scan_history", {"path": str(repo)}, outputs)
        assert "0 distinct secret(s)" in again_h

    assert len(outputs) > 10
    for text in outputs:
        assert_no_secret(text)


@pytest.mark.anyio
async def test_errors_reach_the_agent_and_never_leak(tmp_path):
    repo = planted_repo(tmp_path)
    secret = fake_secrets()["github-token"]
    outputs: list[str] = []
    async with stdio_client(PARAMS) as (read, write_), ClientSession(read, write_) as session:
        await session.initialize()

        res, t = await call(session, "scan_tree", {"path": str(tmp_path / "nope")}, outputs)
        assert res.is_error and "does not exist" in t
        res, t = await call(session, "scan_history", {"path": str(tmp_path)}, outputs)
        assert res.is_error and "not inside a git repository" in t
        res, t = await call(session, "explain_finding", {"id": "f-0000000000000000"}, outputs)
        assert res.is_error and "scan_tree or scan_history first" in t
        # someone pasted a RAW secret as the "id": the error must not echo it back
        res, t = await call(session, "explain_finding", {"id": secret}, outputs)
        assert res.is_error and secret not in t

        # a raw secret pasted into .secretscan-ignore: explicit error, value not echoed
        write(repo, ".secretscan-ignore", secret + "\n")
        res, t = await call(session, "scan_tree", {"path": str(repo)}, outputs)
        assert res.is_error and "line 1" in t and secret not in t
    for text in outputs:
        assert_no_secret(text)


@pytest.mark.anyio
async def test_guard_refuses_output_containing_a_token_shaped_file_name(tmp_path):
    secrets = fake_secrets()
    r = tmp_path / "p"
    r.mkdir()
    git(r, "init", "-q")
    # the file CONTENT leaks a token and the file NAME is itself token-shaped
    name = "gh" + "p_" + "A1" * 18 + ".txt"
    write(r, name, f"x = '{secrets['stripe-live-key']}'\n")
    commit_all(r, "odd")
    async with stdio_client(PARAMS) as (read, write_), ClientSession(read, write_) as session:
        await session.initialize()
        res = await session.call_tool("scan_tree", {"path": str(r)})
        text = res.content[0].text  # type: ignore[union-attr]
        assert res.is_error and "Refusing to return this output" in text
        assert name not in text and secrets["stripe-live-key"] not in text
