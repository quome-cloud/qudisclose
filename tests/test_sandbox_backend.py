"""The sandbox backend seam: the factory selects a backend, and QuomeSandbox satisfies the same
contract as LocalSandbox. The contract test drives QuomeSandbox against a fake Quome SDK sandbox backed
by a real temp directory, so repo seeding, git-in-sandbox and path confinement are genuinely exercised
without a live cluster. (A live end-to-end run needs QUOME_API_KEY + a reachable sandbox.)
"""

from __future__ import annotations

import shlex
import subprocess
import sys
import types
from dataclasses import dataclass
from pathlib import Path

import pytest

from qudisclose.config import SandboxConfig
from qudisclose.security.quome_sandbox import QuomeSandbox
from qudisclose.security.sandbox import LocalSandbox, SandboxBackend, make_sandbox


@pytest.fixture(autouse=True)
def _quome_sdk(monkeypatch):
    """The fake sandbox stands in for the SDK client, but `QuomeSandbox._sh` still imports the SDK's exception type. Without
    the optional `quome` extra, stub that one name so the contract tests run instead of erroring on import."""
    try:
        import quome  # noqa: F401
    except ModuleNotFoundError:
        stub = types.SimpleNamespace(SandboxNotRunningError=type("SandboxNotRunningError", (Exception,), {}))
        monkeypatch.setitem(sys.modules, "quome", stub)


# --------------------------------------------------------------------------- factory


def test_factory_defaults_to_local(tmp_path):
    sb = make_sandbox("c1", repo_path=tmp_path)
    assert isinstance(sb, LocalSandbox)
    assert isinstance(sb, SandboxBackend)


def test_factory_selects_quome_without_network(tmp_path):
    cfg = SandboxConfig(backend="quome", quome_sandbox_id="sbx-1")
    sb = make_sandbox("c1", repo_path=tmp_path, config=cfg)
    assert isinstance(sb, QuomeSandbox)       # construction is lazy — no SDK/network call yet
    assert isinstance(sb, SandboxBackend)


def test_factory_rejects_unknown_backend(tmp_path):
    with pytest.raises(ValueError):
        make_sandbox("c1", repo_path=tmp_path, config=SandboxConfig(backend="nope"))


# --------------------------------------------------------------------------- contract


@dataclass
class _Exec:
    exit_code: int
    stdout: str
    stderr: str


class _FakeFiles:
    def __init__(self, box: "FakeSdkSandbox") -> None:
        self.box = box

    def write(self, path: str, content) -> None:
        p = self.box._map(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(content if isinstance(content, (bytes, bytearray)) else str(content).encode())

    def read(self, path: str) -> bytes:
        p = self.box._map(path)
        if not p.is_file():
            raise FileNotFoundError(path)
        return p.read_bytes()


class FakeSdkSandbox:
    """Emulates quome.Sandbox over a real local dir rooted at <root>/workspace. `run` executes the
    command string with a shell (as the SDK does server-side), translating the /workspace prefix."""

    def __init__(self, root: Path, max_command: int | None = None) -> None:
        self.id = "sbx-fake"
        self.root = root
        (root / "workspace").mkdir(parents=True, exist_ok=True)
        self.files = _FakeFiles(self)
        self.deleted = False
        self.max_command = max_command  # emulate Quome's /exec `command` length cap (None = no cap)

    def _map(self, s: str) -> Path:
        return Path(s.replace("/workspace", str(self.root / "workspace")))

    def run(self, cmd: str, *, timeout: float = 300, working_dir: str = "/workspace", env=None) -> _Exec:
        if self.max_command is not None and len(cmd) > self.max_command:
            # mirrors Quome's 422: {"type":"string_too_long","loc":["body","command"], ...}
            raise ValueError(f"command too long: {len(cmd)} > {self.max_command}")
        cwd = self._map(working_dir)
        cwd.mkdir(parents=True, exist_ok=True)
        mapped = cmd.replace("/workspace", str(self.root / "workspace"))
        p = subprocess.run(mapped, shell=True, cwd=cwd, capture_output=True, text=True, timeout=timeout)
        return _Exec(p.returncode, p.stdout, p.stderr)

    def delete(self) -> None:
        self.deleted = True

    def stop(self) -> None:
        pass


@pytest.fixture
def quome_sb(tmp_path):
    repo = tmp_path / "repo"
    (repo / "pkg").mkdir(parents=True)
    (repo / "pkg" / "files.py").write_text("def resolve(p):\n    return open(p).read()\n")
    (repo / "README.md").write_text("hello\n")
    fake = FakeSdkSandbox(tmp_path / "box")
    cfg = SandboxConfig(backend="quome")
    sb = QuomeSandbox(repo, case_id="case-1", config=cfg, sandbox=fake)
    sb.create()
    yield sb, fake
    sb.destroy()


def test_create_seeds_repo_and_baseline(quome_sb):
    sb, _ = quome_sb
    assert sb.sandbox_id == "sbx-fake"
    files = set(sb.tree())
    assert "pkg/files.py" in files and "README.md" in files
    assert sb.diff().strip() == ""  # baseline committed, so a clean diff is empty


def test_read_and_write_are_confined(quome_sb):
    sb, _ = quome_sb
    assert "resolve" in sb.read("pkg/files.py")
    sb.write("pkg/new.py", "X = 1\n")
    assert sb.read("pkg/new.py") == "X = 1\n"
    for bad in ("../../etc/passwd", "/etc/evil"):
        with pytest.raises(PermissionError):
            sb.read(bad)


def test_run_maps_exit_code(quome_sb):
    sb, _ = quome_sb
    ok = sb.run(["python3", "-c", "print('hi')"])
    assert ok.ok and "hi" in ok.stdout
    bad = sb.run(["python3", "-c", "import sys; sys.exit(1)"])
    assert bad.returncode == 1 and not bad.ok


def test_apply_diff_commit_and_diff(quome_sb):
    sb, _ = quome_sb
    sb.write("pkg/files.py", "def resolve(p):\n    assert '..' not in p\n    return open(p).read()\n")
    assert "assert '..' not in p" in sb.diff()
    sb.commit("fix")
    assert sb.diff().strip() == ""  # committed, working tree clean again


def test_diff_excludes_bytecode_noise(quome_sb):
    """Running tests leaves __pycache__/*.pyc behind; those must NOT land in diff() — a binary .pyc hunk
    breaks `git apply` during patch verification (the real-world no_verified_patch bug)."""
    sb, _ = quome_sb
    sb.write("pkg/__pycache__/files.cpython-311.pyc", "\x00\x01BYTECODE\x02")
    sb.write("pkg/files.py", "def resolve(p):\n    return 1\n")  # a genuine code change
    d = sb.diff()
    assert "pkg/files.py" in d           # real edits still captured
    assert "__pycache__" not in d and ".pyc" not in d  # bytecode excluded


def test_seeds_and_writes_larger_than_exec_command_cap(tmp_path):
    """Regression: Quome caps the /exec `command` field at 10_000 chars, so a repo (or a single
    file) whose base64 payload exceeds that must be streamed in chunks, not inlined in one command.
    A one-line repo slipped under the cap and hid this; a realistic repo does not."""
    import os

    repo = tmp_path / "repo"
    (repo / "pkg").mkdir(parents=True)
    # High-entropy content so the *compressed* seed tarball still blows past the 10_000 cap
    # (repetitive padding would gzip away and hide the seed path).
    big = "X = 1\n" + os.urandom(80_000).hex() + "\n"
    (repo / "pkg" / "big.py").write_text(big)          # ~160 KB, incompressible
    (repo / "small.txt").write_text("hi\n")
    fake = FakeSdkSandbox(tmp_path / "box", max_command=10_000)

    sb = QuomeSandbox(repo, case_id="big", config=SandboxConfig(backend="quome"), sandbox=fake)
    sb.create()                                        # must not raise despite the oversized seed
    files = set(sb.tree())
    assert "pkg/big.py" in files and "small.txt" in files
    assert sb.read("pkg/big.py") == big                # seeded content is intact, not truncated

    huge = "Y = 2\n" + "# written past the cap\n" * 5000
    sb.write("pkg/huge.py", huge)                       # a single large write must chunk too
    assert sb.read("pkg/huge.py") == huge
    sb.destroy()


def test_seed_skips_docs_and_heavy_dirs(tmp_path):
    """Seeding streams one <10k chunk per exec call, so a big docs/ tree would mean hundreds of
    round-trips that can swamp the sandbox. Those dirs (and build/cache/vendor) are skipped — and the
    hunter never targets them (hunter.SKIP_DIRS mirrors this), so nothing references the missing files."""
    repo = tmp_path / "repo"
    (repo / "pkg").mkdir(parents=True)
    (repo / "pkg" / "app.py").write_text("def h():\n    return 1\n")
    for d in ("docs", "build", ".pytest_cache", "node_modules"):
        (repo / d).mkdir()
        (repo / d / "junk.txt").write_text("x" * 50_000)
    fake = FakeSdkSandbox(tmp_path / "box", max_command=10_000)
    sb = QuomeSandbox(repo, case_id="trim", config=SandboxConfig(backend="quome"), sandbox=fake)
    sb.create()
    files = set(sb.tree())
    assert "pkg/app.py" in files
    assert not any(f.startswith(("docs/", "build/", ".pytest_cache/", "node_modules/")) for f in files)
    sb.destroy()


def test_created_sandbox_is_deleted_attached_is_not(tmp_path):
    repo = tmp_path / "r"; repo.mkdir(); (repo / "a.py").write_text("x=1\n")
    # create mode: we made it, so destroy() deletes it
    created = QuomeSandbox(repo, case_id="c2", config=SandboxConfig(backend="quome"),
                           sandbox=FakeSdkSandbox(tmp_path / "b1"))
    created._created = True
    created.create(); f1 = created._sbx; created.destroy()
    assert f1.deleted is True
    # attach mode: id configured, so destroy() leaves the shared sandbox alone
    attached = QuomeSandbox(repo, case_id="c3", config=SandboxConfig(backend="quome", quome_sandbox_id="sbx-x"),
                            sandbox=FakeSdkSandbox(tmp_path / "b2"))
    attached.create(); f2 = attached._sbx; attached.destroy()
    assert f2.deleted is False
