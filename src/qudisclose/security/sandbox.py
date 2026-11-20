"""Execution isolation for the reproducer and patcher agents, and the normative VSLA-F-5 reproduction classifier.

Each case gets its own git worktree; commands run in a subprocess with a scrubbed environment,
rlimits (CPU, memory, file size, process count) and a wall-clock timeout. Network is cut off with
`unshare -n` when available (Linux); on other platforms we fall back to proxy env poisoning. This backend is
VSLA isolation class `process` (VSLA-P-11): a development convenience, named as such in every receipt and in the
policy; a production intake uses the `quome` backend (class `vm`).

The classifier (`run_classified`) is the normative VSLA-F-5 classifier this platform applies to every reproduction,
its own and a finder's (VSLA-P-4, "never the finder's flag"). It runs pytest with `--junitxml` and reads the
runner's own account instead of grepping output:

    securityFailure  :=  collected >= 1 test executed
                     and failures  >= 1 where the failure is an assertion (an `assert` in the test, an
                                       `AssertionError` raised by the code under test, or a pytest `Failed`
                                       such as `DID NOT RAISE`)
                     and errors    == 0 (junit `<error>`: collection, import, syntax or fixture errors)
                     and the run did not time out
                     and the junit report agrees with pytest's own summary line and with the exit code.

A `SystemExit`, a `NameError`, an `ImportError` or any other non-assertion exception is a failure in junit terms but
not a security failure here; a test file that does not collect is an error. Commands that are not pytest cannot be
classified and are reported as `securityFailure: False` with a reason, never True by default. The same run can trace
which modules the test imported (`-X importtime`) or covered (`coverage`, when importable in the sandbox), which is
how the platform decides `touchedSubject` (VSLA-P-4) and says which method it used.

What this defends against, honestly: honest non-security failures (a missing import, a collection error, a timeout,
a bare `sys.exit(1)`) and the simplest forgeries (a test that writes a fake junit file at a guessable path and hard-exits
before pytest writes the real one: the report path is randomised per run, and the report must agree with pytest's
summary line and the exit code). It is NOT sound against a hostile test: the test runs inside the pytest process, with
the runner's uid and cwd, and can in principle forge the report file, the summary line and the exit code together. The
adversarial bar on the Finding track is the coverage check and the receiver's judgement, not this classifier; the paper
and the spec say so."""

from __future__ import annotations

import json
import logging
import os
import re
import resource
import secrets
import shlex
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

if TYPE_CHECKING:
    from qudisclose.config import SandboxConfig

log = logging.getLogger(__name__)

SAFE_ENV_KEYS = ("PATH", "LANG", "LC_ALL", "TERM", "HOME", "TMPDIR", "PYTHONDONTWRITEBYTECODE")

_NETNS_PERMITTED: dict[str, bool] = {}


def _netns_permitted(unshare: str) -> bool:
    """Whether this host lets the platform user create a network namespace. `unshare` can be installed yet forbidden:
    Ubuntu 24.04 ships kernel.apparmor_restrict_unprivileged_userns=1, where `unshare -n` fails with EPERM. A definite
    answer is remembered per binary; a probe that times out on a loaded host is not, so it cannot disable the namespace."""
    if unshare not in _NETNS_PERMITTED:
        try:
            ok = subprocess.run([unshare, "-n", "--", "true"], capture_output=True, timeout=10).returncode == 0
        except subprocess.TimeoutExpired:
            return False
        except OSError:
            ok = False
        if not ok:
            log.warning("%s cannot create a network namespace on this host; the process sandbox cuts egress by proxy "
                        "variables only (netns: none). Use the quome backend for untrusted code.", unshare)
        _NETNS_PERMITTED[unshare] = ok
    return _NETNS_PERMITTED[unshare]


@dataclass
class SandboxResult:
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out

    def excerpt(self, n: int = 4000) -> str:
        text = (self.stdout + ("\n--- stderr ---\n" + self.stderr if self.stderr else ""))
        return text[-n:]


@runtime_checkable
class SandboxBackend(Protocol):
    """The isolation contract the orchestrator and hunter depend on. `LocalSandbox` runs it on this
    host; `QuomeSandbox` runs it in a Quome sandbox VM. Both return `SandboxResult` from `run`/`apply_diff`.

    Implementations must confine `read`/`write` to the sandbox and raise `PermissionError` on escape."""

    def create(self) -> object: ...
    def destroy(self) -> None: ...
    def run(self, argv: list[str], *, timeout: int | None = None) -> SandboxResult: ...
    def read(self, rel: str) -> str: ...
    def write(self, rel: str, content: str) -> None: ...
    def apply_diff(self, diff: str) -> SandboxResult: ...
    def commit(self, message: str) -> None: ...
    def diff(self) -> str: ...
    def tree(self, max_files: int = 400) -> list[str]: ...
    def revision(self) -> str: ...
    def checkout(self, revision: str) -> bool: ...


class LocalSandbox:
    def __init__(self, repo: Path, *, case_id: str, work_root: Path | None = None, cpu_seconds: int = 120,
                 mem_bytes: int = 2 * 1024**3, timeout: int = 180) -> None:
        self.repo = Path(repo).resolve()
        self.case_id = case_id
        self.root = (work_root or self.repo.parent / ".qudisclose-sandboxes").resolve()
        self.path = self.root / case_id
        self.cpu_seconds = cpu_seconds
        self.mem_bytes = mem_bytes
        self.timeout = timeout

    # -- lifecycle

    def create(self) -> Path:
        self.root.mkdir(parents=True, exist_ok=True)
        if self.path.exists():
            self.destroy()
        is_git = (self.repo / ".git").exists()
        if is_git:
            subprocess.run(["git", "-C", str(self.repo), "worktree", "add", "--detach", str(self.path)],
                           check=True, capture_output=True)
        else:
            shutil.copytree(self.repo, self.path, ignore=shutil.ignore_patterns(".qudisclose-sandboxes", ".venv", "__pycache__"))
            # Baseline commit so `diff` and `apply_diff` work for plain directories too.
            git = ["git", "-c", "user.name=qudisclose", "-c", "user.email=qudisclose@localhost", "-C", str(self.path)]
            subprocess.run([*git, "init", "-q"], check=True, capture_output=True)
            subprocess.run([*git, "add", "-A"], check=True, capture_output=True)
            subprocess.run([*git, "commit", "-q", "-m", "baseline", "--no-gpg-sign"], check=True, capture_output=True)
        return self.path

    def destroy(self) -> None:
        if (self.repo / ".git").exists():
            subprocess.run(["git", "-C", str(self.repo), "worktree", "remove", "--force", str(self.path)],
                           capture_output=True)
        shutil.rmtree(self.path, ignore_errors=True)

    # -- execution

    def _env(self) -> dict[str, str]:
        env = {k: os.environ[k] for k in SAFE_ENV_KEYS if k in os.environ}
        # The interpreter running qudisclose (and its test deps) resolves first; repos needing their own
        # toolchain set RepoConfig.test_command accordingly (e.g. "uv run pytest").
        env["PATH"] = str(Path(sys.executable).parent) + os.pathsep + env.get("PATH", "/usr/bin:/bin")
        env["HOME"] = str(self.path)
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        # Poison proxies so accidental egress fails fast even where unshare is unavailable.
        for k in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
            env[k] = "http://127.0.0.1:9"
        env["NO_PROXY"] = ""
        return env

    def _preexec(self) -> None:
        resource.setrlimit(resource.RLIMIT_CPU, (self.cpu_seconds, self.cpu_seconds))
        resource.setrlimit(resource.RLIMIT_FSIZE, (256 * 1024**2, 256 * 1024**2))
        if sys.platform.startswith("linux"):
            resource.setrlimit(resource.RLIMIT_AS, (self.mem_bytes, self.mem_bytes))
            resource.setrlimit(resource.RLIMIT_NPROC, (256, 256))

    @staticmethod
    def netfilter() -> str:
        """How network egress is cut for sandboxed commands on this host: a network namespace (`unshare -n`, Linux), the
        macOS `sandbox-exec` profile `(deny network*)`, or nothing but proxy poisoning (`none`)."""
        unshare = shutil.which("unshare")
        if sys.platform.startswith("linux") and unshare and _netns_permitted(unshare):
            return "unshare"
        if sys.platform == "darwin" and os.path.exists("/usr/bin/sandbox-exec"):
            return "sandbox-exec"
        return "none"

    def isolation_detail(self) -> dict[str, Any]:
        """What this `process`-class sandbox actually enforces, for the receipt (VSLA-P-11): the isolation class is a claim
        a verifier can hold a platform to only if the receipt says what the class meant on that host."""
        return {"netns": self.netfilter(), "rlimits": ["cpu", "fsize"] + (["as", "nproc"] if sys.platform.startswith("linux") else []),
                "filesystem": "worktree; host filesystem readable (process isolation)", "principal": "platform uid"}

    def run(self, argv: list[str], *, timeout: int | None = None) -> SandboxResult:
        cmd = list(argv)
        nf = self.netfilter()
        if nf == "unshare":
            cmd = ["unshare", "-n", "--", *cmd]
        elif nf == "sandbox-exec":
            cmd = ["/usr/bin/sandbox-exec", "-p", "(version 1)(allow default)(deny network*)", *cmd]
        try:
            p = subprocess.run(cmd, cwd=self.path, env=self._env(), capture_output=True, text=True,
                               timeout=timeout or self.timeout, preexec_fn=self._preexec)
        except subprocess.TimeoutExpired as e:
            return SandboxResult(returncode=-1, stdout=(e.stdout or b"").decode() if isinstance(e.stdout, bytes) else (e.stdout or ""),
                                 stderr="timed out", timed_out=True)
        return SandboxResult(returncode=p.returncode, stdout=p.stdout[-200_000:], stderr=p.stderr[-200_000:])

    # -- file helpers (paths are confined to the sandbox)

    def _confine(self, rel: str) -> Path:
        p = (self.path / rel).resolve()
        if not str(p).startswith(str(self.path) + os.sep) and p != self.path:
            raise PermissionError(f"path escapes sandbox: {rel}")
        return p

    def read(self, rel: str) -> str:
        return self._confine(rel).read_text()

    def write(self, rel: str, content: str) -> None:
        p = self._confine(rel)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)

    def apply_diff(self, diff: str) -> SandboxResult:
        r = subprocess.run(["git", "apply", "--whitespace=nowarn", "-"], cwd=self.path, input=diff,
                           capture_output=True, text=True, env=self._env())
        if r.returncode != 0:
            r = subprocess.run(["patch", "-p1", "--forward", "--batch"], cwd=self.path, input=diff,
                               capture_output=True, text=True, env=self._env())
        return SandboxResult(returncode=r.returncode, stdout=r.stdout, stderr=r.stderr)

    def commit(self, message: str) -> None:
        """Fold the current working-tree state into the sandbox baseline (so later `diff` excludes it)."""
        git = ["git", "-c", "user.name=qudisclose", "-c", "user.email=qudisclose@localhost", "-C", str(self.path)]
        subprocess.run([*git, "add", "-A"], check=True, capture_output=True)
        subprocess.run([*git, "commit", "-q", "--allow-empty", "-m", message, "--no-gpg-sign"], check=True, capture_output=True)

    def revision(self) -> str:
        """The git commit the case runs against (VSLA subject[1]); the baseline commit for a plain directory."""
        r = subprocess.run(["git", "rev-parse", "HEAD"], cwd=self.path, capture_output=True, text=True)
        return r.stdout.strip() or "unknown"

    def checkout(self, revision: str) -> bool:
        """Put the sandbox at `revision` (VSLA-P-4: re-execute at the subject revision). False if the commit is not in
        the repository this sandbox was created from, which the caller reports as `environment-error`."""
        if not re.fullmatch(r"[0-9a-f]{7,40}", revision or ""):
            return False
        r = subprocess.run(["git", "checkout", "-q", "--detach", revision], cwd=self.path, capture_output=True, text=True)
        return r.returncode == 0 and self.revision().startswith(revision)

    def diff(self) -> str:
        if (self.path / ".git").exists() or (self.repo / ".git").exists():
            r = subprocess.run(["git", "add", "-N", "."], cwd=self.path, capture_output=True, text=True)
            r = subprocess.run(["git", "diff"], cwd=self.path, capture_output=True, text=True)
            return r.stdout
        return ""

    def tree(self, max_files: int = 400) -> list[str]:
        out: list[str] = []
        for p in sorted(self.path.rglob("*")):
            if any(part.startswith(".") or part in ("__pycache__", "node_modules", ".venv") for part in p.relative_to(self.path).parts):
                continue
            if p.is_file():
                out.append(str(p.relative_to(self.path)))
            if len(out) >= max_files:
                break
        return out


# ----------------------------------------------------------------------------- VSLA-F-5 classifier

_ASSERTION_RE = re.compile(r"^\s*(assert\b|AssertionError\b|Failed\b|_pytest\.outcomes\.Failed\b|pytest\.fail\b)")
_PYTHONS = ("python", "python3", "python3.12", "python3.13", "python3.14")
_SUMMARY_RE = re.compile(r"(\d+) (passed|failed|errors?|skipped|xfailed|xpassed|deselected|warnings?)\b")
TOUCHED_MEANS = {"importtime": "imported", "coverage": "covered", "none": "none"}


@dataclass
class Classification:
    """The platform's own account of one reproduction run (VSLA-F-5 / VSLA-P-4)."""

    security_failure: bool
    reason: str
    classifier: str = "pytest-junit"       # "pytest-junit" | "none"
    collected: int = 0
    failures: int = 0
    assertion_failures: int = 0
    errors: int = 0
    timed_out: bool = False
    consistent: bool | None = None          # junit report vs pytest summary line vs exit code
    touched_subject: bool | None = None     # None = not asked / no method available
    touched_method: str = "none"            # "coverage" | "importtime" | "none"
    imported: list[str] = field(default_factory=list)   # module names (importtime) or file paths (coverage) the run touched

    @property
    def touched_means(self) -> str:
        """What `touched_subject` means, honestly: "imported" (the run imported a module of the subject package) or
        "covered" (a file under the subject package executed under coverage)."""
        return TOUCHED_MEANS.get(self.touched_method, "none")

    def to_dict(self) -> dict[str, Any]:
        return {k: v for k, v in self.__dict__.items() if k != "imported"} | {"touched_means": self.touched_means}


def _summary_counts(stdout: str) -> dict[str, int] | None:
    """pytest's own one-line summary (`1 failed, 2 passed in 0.1s`), from the end of stdout; None when absent."""
    for ln in reversed(stdout.splitlines()[-30:]):
        found = _SUMMARY_RE.findall(ln)
        if found and (" in " in ln or "no tests ran" in ln):
            out: dict[str, int] = {}
            for n, k in found:
                out[k.rstrip("s") if k.startswith("error") else k] = int(n)
            return out
        if "no tests ran" in ln:
            return {}
    return None


def _consistent(collected: int, failures: int, errors: int, summary: dict[str, int] | None, returncode: int) -> tuple[bool, str]:
    """The junit report, pytest's summary line and the exit code must tell one story (pytest exit 0 = all passed, 1 = tests
    failed, 2 = interrupted/collection error, 5 = nothing collected)."""
    if summary is None:
        return False, "no pytest summary line"
    s_failed, s_passed, s_error = summary.get("failed", 0), summary.get("passed", 0) + summary.get("xpassed", 0), summary.get("error", 0)
    if s_failed != failures or s_error != errors or s_passed != collected - failures - summary.get("skipped", 0) - summary.get("xfailed", 0):
        return False, f"junit (collected={collected} failures={failures} errors={errors}) disagrees with summary {summary}"
    expected_exit = 0 if (failures == 0 and errors == 0 and collected > 0) else 1 if (failures > 0 and errors == 0) else None
    if expected_exit is not None and returncode != expected_exit:
        return False, f"exit {returncode} disagrees with the report (expected {expected_exit})"
    if collected == 0 and errors == 0 and returncode not in (5, 2):
        return False, f"nothing collected but exit {returncode}"
    return True, "ok"


def _is_pytest(argv: list[str]) -> bool:
    base = Path(argv[0]).name if argv else ""
    return base == "pytest" or (base in _PYTHONS and len(argv) > 2 and argv[1] == "-m" and argv[2] == "pytest")


def _with_importtime(argv: list[str]) -> list[str]:
    """`-X importtime` writes to fd 2 at the C level; pytest's default fd capture would swallow the imports made during
    collection (where the test module imports the subject), so capture is narrowed to sys-level streams."""
    base = Path(argv[0]).name
    if base in _PYTHONS:
        return [argv[0], "-X", "importtime", *argv[1:], "--capture=sys"]
    return ["python", "-X", "importtime", "-m", "pytest", *argv[1:], "--capture=sys"]     # bare `pytest ...`


def _with_coverage(argv: list[str], cov: str) -> list[str]:
    base = Path(argv[0]).name
    rest = argv[3:] if base in _PYTHONS else argv[1:]
    return [argv[0] if base in _PYTHONS else "python", "-m", "coverage", "run", f"--data-file={cov}", "-m", "pytest", *rest]


def _strip_importtime(text: str) -> tuple[str, list[str]]:
    """Separate `-X importtime` lines (`import time: ... | module`) from the program's own output."""
    kept, mods = [], []
    for ln in text.splitlines():
        if ln.startswith("import time:"):
            parts = ln.split("|")
            if len(parts) >= 3:
                mods.append(parts[-1].strip())
        else:
            kept.append(ln)
    return "\n".join(kept), mods


def _parse_junit(xml_text: str) -> tuple[int, int, int, int]:
    """(collected, failures, assertion_failures, errors) from a pytest junit report."""
    import xml.etree.ElementTree as ET

    root = ET.fromstring(xml_text)
    cases = list(root.iter("testcase"))
    collected = failures = assertion = errors = 0
    for tc in cases:
        if tc.find("error") is not None:
            errors += 1
            continue
        collected += 1
        f = tc.find("failure")
        if f is not None:
            failures += 1
            msg = (f.get("message") or "") + "\n" + (f.text or "")
            if _ASSERTION_RE.match(msg) or "\nE       assert " in msg or "\nE   AssertionError" in msg or "DID NOT RAISE" in msg:
                assertion += 1
    # a collection error shows up as a testcase with <error> and no name of its own; an empty suite has none at all
    return collected, failures, assertion, errors


def run_classified(sandbox: "SandboxBackend", command: str, *, subject: str | None = None, extra_files: list[str] | None = None,
                   timeout: int | None = None) -> tuple[SandboxResult, Classification]:
    """Run `command` (a reproduction test) in the sandbox and classify the result per VSLA-F-5. With `subject` (the
    package the report names) and/or `extra_files` (a patch's files), also decide `touched_subject`: whether the run
    imported or covered a file of that package, via `coverage` when importable in the sandbox, else `-X importtime`."""
    argv = shlex.split(command)
    if not argv or not _is_pytest(argv):
        r = sandbox.run(argv, timeout=timeout) if argv else SandboxResult(returncode=127, stdout="", stderr="empty command")
        return r, Classification(False, "classifier supports pytest only; command was not classified", classifier="none", timed_out=r.timed_out)
    want_touch = subject is not None or bool(extra_files)
    method = "none"
    token = secrets.token_hex(8)                       # per-run report names: a test cannot pre-write a report at a known path
    junit_path, cov_path = f".qud-junit-{token}.xml", f".qud-cov-{token}"
    run_argv = [*argv, f"--junitxml={junit_path}"]
    if want_touch:
        py = argv[0] if Path(argv[0]).name in _PYTHONS else "python"
        if sandbox.run([py, "-c", "import coverage"], timeout=60).returncode == 0:
            method, run_argv = "coverage", [*_with_coverage(argv, cov_path), f"--junitxml={junit_path}"]
        else:
            method, run_argv = "importtime", [*_with_importtime(argv), f"--junitxml={junit_path}"]
    r = sandbox.run(run_argv, timeout=timeout)
    touched_names: list[str] = []
    if method == "importtime":
        stderr, touched_names = _strip_importtime(r.stderr)
        r = SandboxResult(returncode=r.returncode, stdout=r.stdout, stderr=stderr, timed_out=r.timed_out)
    elif method == "coverage":
        py = run_argv[0]
        if sandbox.run([py, "-m", "coverage", "json", f"--data-file={cov_path}", "-o", f"{cov_path}.json", "-q"], timeout=120).returncode == 0:
            try:
                touched_names = list(json.loads(sandbox.read(f"{cov_path}.json")).get("files", {}))
            except Exception:
                touched_names = []
        sandbox.run(["rm", "-f", cov_path, f"{cov_path}.json"], timeout=30)
    try:
        junit = sandbox.read(junit_path)
    except Exception:
        junit = ""
    sandbox.run(["rm", "-f", junit_path], timeout=30)
    if r.timed_out:
        c = Classification(False, "timed out", timed_out=True)
    elif not junit:
        c = Classification(False, f"no junit report produced (exit {r.returncode}: runner did not start or crashed)")
    else:
        try:
            collected, failures, assertion, errors = _parse_junit(junit)
        except Exception as exc:
            c = Classification(False, f"junit report unreadable: {exc!r}")
        else:
            consistent, why = _consistent(collected, failures, errors, _summary_counts(r.stdout), r.returncode)
            ok = collected >= 1 and assertion >= 1 and errors == 0 and consistent
            reason = ("assertion failure in a collected test" if ok else f"runner report inconsistent (possible forgery): {why}" if not consistent
                      else "collection/import/fixture error" if errors else "no test collected" if collected == 0
                      else "no assertion failure (test passed, or failed with a non-assertion exception)" if assertion == 0 else "")
            c = Classification(ok, reason, collected=collected, failures=failures, assertion_failures=assertion, errors=errors, consistent=consistent)
    if want_touch and method != "none":
        c.touched_method, c.imported = method, touched_names
        c.touched_subject = _touches(touched_names, method, subject, extra_files or [])
    return r, c


def sandbox_fault(sandbox: "SandboxBackend") -> str | None:
    """Why the sandbox itself cannot run a command, or None when it can. Tells a platform failure apart from a test that
    crashed its own runner: only the first is the platform's fault (VSLA-P-4 `environment-error`, VSLA-P-6 no entry)."""
    r = sandbox.run(["true"], timeout=60)
    if r.returncode == 0:
        return None
    return f"the platform sandbox cannot run a command (exit {r.returncode}): {r.stderr.strip()[-200:]}"


def _touches(names: list[str], method: str, subject: str | None, extra_files: list[str]) -> bool:
    files = {Path(f).as_posix() for f in extra_files}
    for n in names:
        if method == "importtime":
            top = n.split(".", 1)[0]
            if subject and top == subject:
                return True
            if (n.replace(".", "/") + ".py") in files or (n.replace(".", "/") + "/__init__.py") in files:
                return True
        else:
            p = Path(n).as_posix()
            parts = Path(n).parts
            if subject and subject in parts[:-1]:
                return True
            if any(p == f or p.endswith("/" + f) for f in files):
                return True
    return False


# Backwards-compatible alias: `Sandbox` was the local backend before the seam was extracted.
Sandbox = LocalSandbox


def make_sandbox(case_id: str, *, repo_path: Path | str,
                 config: "SandboxConfig | None" = None) -> SandboxBackend:
    """Construct the sandbox backend selected by `config.backend` ("local" by default, or "quome").

    This is the single place a backend is chosen; callers never instantiate a concrete sandbox."""
    backend = getattr(config, "backend", "local")
    if backend == "quome":
        from qudisclose.security.quome_sandbox import QuomeSandbox
        assert config is not None  # a quome backend cannot be selected without a config
        return QuomeSandbox(Path(repo_path), case_id=case_id, config=config)
    if backend != "local":
        raise ValueError(f"unknown sandbox backend: {backend!r}")
    return LocalSandbox(Path(repo_path), case_id=case_id)
