"""The local sandbox must not let code that ran inside a case (a finder's reproduction test) get executed later by the
platform's own git calls, outside the test's confinement and with the platform's environment.

Reported privately against a3e24ae: cases were git worktrees, so they shared the repository's `.git` (hooks and config);
a test could plant a hook there and the platform's next `git commit` / `checkout` / `worktree add` ran it unconfined."""

from __future__ import annotations

import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from qudisclose.security.sandbox import LocalSandbox

SECRET = "QUD_TEST_PLATFORM_SECRET"
HOOKS = ("pre-commit", "post-commit", "post-checkout", "post-index-change", "prepare-commit-msg", "commit-msg",
         "pre-applypatch", "applypatch-msg", "reference-transaction")


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@localhost", "-C", str(repo), *args],
                          check=True, capture_output=True, text=True).stdout.strip()


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    r = tmp_path / "repo"
    r.mkdir()
    (r / "mod.py").write_text("x = 1\n")
    _git(r, "init", "-q")
    _git(r, "add", "-A")
    _git(r, "commit", "-q", "-m", "one", "--no-gpg-sign")
    (r / "mod.py").write_text("x = 2\n")
    _git(r, "commit", "-q", "-am", "two", "--no-gpg-sign")
    return r


def _hostile(marker: Path) -> str:
    """What a hostile reproduction test does from inside the sandbox: plant hooks wherever git says the hooks live, and
    point the repository config at commands of its own."""
    return textwrap.dedent(f"""
        import os, stat, subprocess, pathlib
        payload = "#!/bin/sh\\nenv > {marker}.hook.$$\\n"
        def out(*a):
            return subprocess.run(["git", *a], capture_output=True, text=True).stdout.strip()
        dirs = {{out("rev-parse", "--git-common-dir"), out("rev-parse", "--git-dir")}}
        for d in filter(None, dirs):
            hooks = pathlib.Path(d).resolve() / "hooks"
            hooks.mkdir(parents=True, exist_ok=True)
            for name in {HOOKS!r}:
                p = hooks / name
                p.write_text(payload)
                p.chmod(p.stat().st_mode | stat.S_IXUSR)
        cmd = "sh -c 'env > {marker}.cfg.$$; cat'"
        for k, v in (("core.fsmonitor", cmd), ("diff.external", cmd), ("filter.x.clean", cmd), ("filter.x.smudge", cmd),
                     ("core.pager", cmd), ("core.editor", cmd)):
            subprocess.run(["git", "config", k, v])
        pathlib.Path(".gitattributes").write_text("* filter=x\\n")
        pathlib.Path(".gitconfig").write_text("[core]\\n\\tfsmonitor = " + cmd + "\\n")
        pathlib.Path("dropped.txt").write_text("x\\n")
    """)


def _exercise(sb: LocalSandbox, repo: Path, first: str) -> None:
    """Every git call the platform makes on a case after a test has run in it."""
    sb.commit("qudisclose: reproduction test")
    sb.write("mod.py", "x = 3\n")
    sb.diff()
    sb.apply_diff("--- a/mod.py\n+++ b/mod.py\n@@ -1 +1 @@\n-x = 3\n+x = 4\n")
    sb.revision()
    sb.checkout(first)
    sb.destroy()
    sb.create()                       # the next case on the same repository
    other = LocalSandbox(repo, case_id="other")
    other.create()
    other.commit("x")
    other.destroy()
    sb.destroy()


def test_sandbox_does_not_share_the_repository_git_dir(repo: Path) -> None:
    sb = LocalSandbox(repo, case_id="own-git")
    sb.create()
    try:
        common = Path(sb.run(["git", "rev-parse", "--git-common-dir"]).stdout.strip())
        common = (sb.path / common).resolve()
        assert common == (sb.path / ".git").resolve()
        assert sb.revision() == _git(repo, "rev-parse", "HEAD")
        assert sb.read("mod.py") == "x = 2\n"
        assert _git(repo, "worktree", "list").count("\n") == 0      # nothing registered in the repository
    finally:
        sb.destroy()


def test_hostile_test_cannot_run_code_through_platform_git(repo: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(SECRET, "signing-key-material")
    marker = tmp_path / "pwned"
    before = sorted(p.name for p in (repo / ".git" / "hooks").iterdir()) if (repo / ".git" / "hooks").exists() else []
    config_before = (repo / ".git" / "config").read_text()
    first = _git(repo, "rev-list", "--max-parents=0", "HEAD")
    sb = LocalSandbox(repo, case_id="hostile")
    sb.create()
    sb.write("evil.py", _hostile(marker))
    assert sb.run([sys.executable, "evil.py"]).ok
    _exercise(sb, repo, first)

    # nothing the test planted reached the repository the platform (and the operator) keep using
    after = sorted(p.name for p in (repo / ".git" / "hooks").iterdir()) if (repo / ".git" / "hooks").exists() else []
    assert after == before
    assert (repo / ".git" / "config").read_text() == config_before
    # no hook ran at all, and anything else git was talked into running saw only the scrubbed sandbox environment
    leaked = list(tmp_path.glob("pwned.*"))
    assert not [p for p in leaked if ".hook." in p.name], "a planted hook was executed by a platform git call"
    for p in leaked:
        assert SECRET not in p.read_text(), f"{p.name} ran with the platform's environment"


def test_checkout_reaches_any_commit_of_the_repository(repo: Path) -> None:
    first = _git(repo, "rev-list", "--max-parents=0", "HEAD")
    sb = LocalSandbox(repo, case_id="rev")
    sb.create()
    try:
        assert sb.checkout(first)
        assert sb.read("mod.py") == "x = 1\n"
        assert not sb.checkout("0" * 40)
    finally:
        sb.destroy()


def test_diff_commit_and_apply_still_work(repo: Path) -> None:
    sb = LocalSandbox(repo, case_id="flow")
    sb.create()
    try:
        sb.write("tests/test_new.py", "def test_x():\n    assert True\n")
        sb.commit("qudisclose: reproduction test")
        assert sb.diff() == ""
        r = sb.apply_diff("--- a/mod.py\n+++ b/mod.py\n@@ -1 +1 @@\n-x = 2\n+x = 5\n")
        assert r.ok, r.stderr
        d = sb.diff()
        assert "+x = 5" in d and "test_new" not in d
        assert (repo / "mod.py").read_text() == "x = 2\n"
    finally:
        sb.destroy()


# ----------------------------------------------------------------------------- the repository is read-only to a case

def _snapshot(root: Path) -> dict[str, bytes]:
    return {str(p.relative_to(root)): p.read_bytes() for p in sorted(root.rglob("*")) if p.is_file() and not p.is_symlink()}


def test_a_case_cannot_write_to_the_repository_by_absolute_path(repo: Path) -> None:
    """A test runs as the platform's uid, so nothing but the sandbox stops it writing a hook into the repository's own
    `.git/hooks` for the operator's next `git checkout` to run."""
    sb = LocalSandbox(repo, case_id="ro")
    if sb.repo_guard() == "none":
        pytest.skip("no way to make the repository read-only to a case on this host")
    before = _snapshot(repo)
    sb.create()
    try:
        sb.write("evil.py", textwrap.dedent(f"""
            import os, pathlib
            repo = pathlib.Path({str(repo)!r})
            alt = pathlib.Path(open(".git/objects/info/alternates").read().strip()).parent
            assert alt.resolve() == (repo / ".git").resolve()
            tried = 0
            def attempt(fn):
                global tried
                tried += 1
                try:
                    fn()
                except OSError:
                    pass
            hook = repo / ".git" / "hooks" / "post-checkout"
            attempt(lambda: (hook.parent.mkdir(exist_ok=True), hook.write_text("#!/bin/sh\\necho pwned\\n"), hook.chmod(0o755)))
            attempt(lambda: (repo / ".git" / "config").open("a").write("[core]\\n\\tfsmonitor = sh -c 'echo pwned'\\n"))
            attempt(lambda: (repo / "mod.py").write_text("x = 'pwned'\\n"))
            attempt(lambda: (repo / "new.py").write_text("pwned\\n"))
            attempt(lambda: (os.link(repo / ".git" / "config", "hard"), open("hard", "a").write("[x]\\n")))
            attempt(lambda: os.rename(repo / "mod.py", "stolen.py"))
            attempt(lambda: os.unlink(repo / "mod.py"))
            for p in pathlib.Path("/proc").glob("[0-9]*/root"):          # Linux: another process's view of the filesystem
                attempt(lambda p=p: (p / str(repo).lstrip("/") / "viaproc.py").write_text("pwned\\n"))
            pathlib.Path("inside.txt").write_text(str(tried))
        """))
        r = sb.run([sys.executable, "evil.py"])
        assert r.ok, r.stdout + r.stderr
        assert int(sb.read("inside.txt")) >= 7            # the script ran to the end, and the case itself is writable
        assert _snapshot(repo) == before
        # the platform's own git still works on the case
        sb.commit("after")
        assert sb.revision() != _git(repo, "rev-parse", "HEAD")
    finally:
        sb.destroy()


def test_isolation_detail_says_whether_the_repository_is_read_only(repo: Path) -> None:
    sb = LocalSandbox(repo, case_id="detail")
    assert sb.isolation_detail()["repository"] in ("read-only (sandbox-exec)", "writable")
    assert (sb.isolation_detail()["repository"] == "writable") == (sb.repo_guard() == "none")
