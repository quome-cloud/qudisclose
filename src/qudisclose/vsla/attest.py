"""Build and sign VSLA statements for a case (the finder role; spec requirements VSLA-F-1..F-20).

qudisclose is a finder for every case it verifies: the Finding statement is produced once the orchestrator's own
re-run of the reproduction test fails for a security reason (per the normative classifier), the Patch statement once a
diff has passed reproduction, the suite and the review. Digests go in; bodies stay out. Every statement is produced in
two profiles: `embargoed` (command, test path and files touched are digests, so the statement can be published while
the case is open) and `published` (plaintext), and the platform exposes only the embargoed one until the case is public."""

from __future__ import annotations

import hashlib
import platform as _platform
import re
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from qudisclose import __version__
from qudisclose.models import PatchResult, ReportSubmission, ReproductionResult, ReviewVerdict
from qudisclose.security.keys import Identity
from qudisclose.vsla.canonical import canonical, digest, sha256_hex
from qudisclose.vsla.dsse import sign_envelope, statement
from qudisclose.vsla.environment import EnvironmentAttestor, NoEnvironment
from qudisclose.vsla.merkle import leaf_bytes, merkle_root

REPORT_FIELDS = ("title", "description", "repo", "package", "affected_versions", "proof_of_concept", "cwe", "cvss_vector", "suggested_fix")
AUTHORIZATION_BASES = ("ownership", "program", "engagement", "safe-harbour")

# Paths a Patch-track L2 statement may not touch (VSLA-F-18): where real supply-chain compromises have landed.
# Ported verbatim from the reference verifier.
NON_SOURCE_PATTERNS = (r"(^|/)\.github/", r"(^|/)\.gitlab-ci", r"(^|/)Makefile$", r"(^|/)CMakeLists\.txt$", r"(^|/)configure(\.ac)?$",
                       r"(^|/)setup\.(py|cfg)$", r"(^|/)pyproject\.toml$", r"(^|/)package(-lock)?\.json$", r"(^|/)Cargo\.(toml|lock)$",
                       r"(^|/)go\.(mod|sum)$", r"(^|/)requirements[^/]*\.txt$", r"(^|/)Dockerfile", r"(^|/)tests?/fixtures?/",
                       r"(^|/)testdata/", r"\.(bin|so|dll|dylib|exe|jar|wasm|gz|xz|zip|tar|7z|png|jpg|pdf|pth)$", r"(^|/)scripts?/release",
                       r"(^|/)\.pre-commit", r"(^|/)tox\.ini$", r"(^|/)noxfile\.py$", r"(^|/)conftest\.py$", r"(^|/)MANIFEST\.in$",
                       r"(^|/)\.gitmodules$", r"(^|/)\.gitattributes$", r"(^|/)sitecustomize\.py$", r"(^|/)usercustomize\.py$")
# Diff headers that change something a path pattern cannot see: a rename, a mode change, a binary blob (VSLA-F-18).
_NON_TEXT_HEADERS = re.compile(r"^(rename (from|to) |old mode |new mode |GIT binary patch|Binary files .* differ|similarity index |dissimilarity index |copy (from|to) )")


def report_digest(sub: ReportSubmission | dict[str, Any]) -> str:
    """subject[0]: the fields that describe the bug, never contact or credit. It identifies this report, not the bug."""
    d = sub.model_dump() if isinstance(sub, ReportSubmission) else sub
    return sha256_hex(canonical({k: d.get(k) for k in REPORT_FIELDS if d.get(k) not in (None, [], "")}))


def harness_digest() -> dict[str, str]:
    """VSLA-F-14: measured at load, not copied from a manifest: SHA-256 over the installed qudisclose sources."""
    root = Path(__file__).resolve().parents[1]
    h = hashlib.sha256()
    for p in sorted(root.rglob("*.py")):
        h.update(p.relative_to(root).as_posix().encode() + b"\0" + p.read_bytes() + b"\0")
    return {"sha256": h.hexdigest()}


def sandbox_digest(backend: str, isolation: str | None = None) -> dict[str, str]:
    """A digest of the re-execution environment as this host can describe it (backend, isolation class, interpreter, platform)."""
    return digest(canonical({"backend": backend, "isolation": isolation or sandbox_isolation(backend), "python": sys.version.split()[0], "platform": _platform.platform()}))


def sandbox_isolation(backend: str) -> str:
    """VSLA-P-11 isolation class per backend: `process` for the local backend (a development convenience), `vm` for Quome."""
    return "vm" if backend == "quome" else "process"


def iso(t: datetime) -> str:
    return t.astimezone(UTC).isoformat().replace("+00:00", "Z")


def non_source_paths(paths: list[str]) -> list[str]:
    return [p for p in paths if any(re.search(pat, p) for pat in NON_SOURCE_PATTERNS)]


def scope_of(paths: list[str], diff: str | None = None) -> str:
    """VSLA-F-18: `source-only` unless the diff touches build, CI, fixtures, binaries, manifests or release tooling, or
    (when the diff text is given) renames a file, changes a mode or carries a binary patch, which no path pattern sees."""
    if diff is not None and non_text_changes(diff):
        return "mixed"
    return "mixed" if non_source_paths(paths) else "source-only"


def non_text_changes(diff: str) -> list[str]:
    """Header lines of a git diff that rename, re-mode or binary-patch a file: each makes the scope `mixed`."""
    return [ln for ln in diff.splitlines() if _NON_TEXT_HEADERS.match(ln)]


def diff_paths(diff: str) -> list[str]:
    """Files a diff touches on either side (so deletions, renames, mode changes and binary patches count), sorted. Reads
    `diff --git a/x b/y` headers, `rename from/to`, `copy from/to` and the `---`/`+++` lines."""
    out: set[str] = set()
    for ln in diff.splitlines():
        m = re.match(r"^diff --git a/(.+?) b/(.+)$", ln)
        if m:
            out.update(p.strip() for p in m.groups())
            continue
        m = re.match(r"^(?:rename|copy) (?:from|to) (.+)$", ln)
        if m:
            out.add(m.group(1).strip())
            continue
        for prefix in ("+++ b/", "--- a/", "+++ ", "--- "):
            if ln.startswith(prefix):
                p = ln[len(prefix):].split("\t")[0].strip()
                if p and p != "/dev/null":
                    out.add(p)
                break
    return sorted(out)


def model_family(provider: str, name: str) -> str:
    """The model family used to judge reviewer/patcher diversity (VSLA-P-10): anthropic -> claude; otherwise the
    leading alphabetic run of the model name before any ':' tag or version digit (qwen3.8:27b -> qwen, glm-4.6 -> glm)."""
    if provider == "anthropic" or name.lower().startswith("claude"):
        return "claude"
    token = name.split(":", 1)[0].strip().lower()
    m = re.match(r"[a-z]+", token)
    return m.group(0) if m else (token or provider or "unknown")


@dataclass(frozen=True)
class MBOMEntry:
    role: str
    provider: str
    name: str
    serving: str                        # api | self-hosted | tee
    family: str | None = None
    version: str | None = None
    weights_digest: str | None = None   # sha256 hex of the loaded weight bytes (never of the model name)
    weights_unmeasured: bool = False    # self-hosted but the bytes were not hashed: honest, caps Environment at L1
    quantization: str | None = None
    attestation: dict[str, Any] | None = None   # provider-signed DSSE weights attestation

    def to_dict(self) -> dict[str, Any]:
        m: dict[str, Any] = {"role": self.role, "provider": self.provider, "name": self.name, "serving": self.serving,
                             "family": self.family or model_family(self.provider, self.name)}
        if self.version:
            m["version"] = self.version
        if self.serving in ("self-hosted", "tee"):
            w: dict[str, Any] = {"digest": {"sha256": self.weights_digest}} if self.weights_digest else {"unmeasured": True}
            if self.quantization:
                w["quantization"] = self.quantization
            if self.attestation:
                w["attestation"] = self.attestation
            m["weights"] = w
        return m


class Attestor:
    def __init__(self, *, finder: Identity, operator: str, channel: dict[str, Any] | None = None,
                 environment: EnvironmentAttestor | None = None, enclave: Identity | None = None,
                 authorization: dict[str, Any] | None = None,
                 floor: float = 0.6, min_entries: int = 5, min_countersigners: int = 2, min_age_days: float = 30) -> None:
        self.finder, self.operator, self.channel = finder, operator, channel
        self.environment = environment or NoEnvironment()
        self.enclave = enclave
        auth = dict(authorization or {"basis": "ownership"})
        if auth.get("basis") not in AUTHORIZATION_BASES:
            raise ValueError(f"authorization.basis must be one of {AUTHORIZATION_BASES}, got {auth.get('basis')!r}")
        self.authorization = {"basis": auth["basis"], **({"ref": str(auth["ref"])[:500]} if auth.get("ref") else {})}
        self.floor, self.min_entries, self.min_countersigners, self.min_age_days = floor, min_entries, min_countersigners, min_age_days
        self.harness = {"name": "qudisclose", "version": __version__, "digest": harness_digest()}

    # -- helpers

    def _finder(self) -> dict[str, Any]:
        return {"identity": self.finder.name, "publicKey": f"ed25519:{self.finder.public_hex}", "operator": self.operator, "harness": self.harness}

    def _history_meets_floor(self, history: dict[str, Any] | None) -> bool:
        if not history or history.get("entries", 0) < self.min_entries or history.get("countersigners", 0) < self.min_countersigners \
                or history.get("score", 0) < self.floor or not history.get("oldestAt"):
            return False
        oldest = datetime.fromisoformat(str(history["oldestAt"]).replace("Z", "+00:00"))
        return (datetime.now(UTC) - oldest).total_seconds() / 86400 >= self.min_age_days

    def _claimed(self, history: dict[str, Any] | None, env: dict[str, Any] | None, mbom: list[MBOMEntry]) -> int:
        lvl = 1
        if self.channel and self._history_meets_floor(history):
            lvl = 2
        if lvl == 2 and env and self.enclave is not None and all(m.serving in ("self-hosted", "tee") for m in mbom):
            lvl = 3
        return lvl

    def _sign(self, subject: list[dict[str, Any]], pred: dict[str, Any], env: dict[str, Any] | None) -> dict[str, Any]:
        signers = [(f"finder:{self.finder.name}", self.finder)]
        if env and self.enclave is not None:
            signers.append((f"enclave:{env['type']}:{env['measurement']['value'][:16]}", self.enclave))
        return sign_envelope(statement(subject, pred), signers)

    def _common(self, *, sub: ReportSubmission, leaves: list[dict[str, Any]], mbom: list[MBOMEntry], repro: ReproductionResult,
                rerun: dict[str, Any], revision: str, sandbox_backend: str, scanner_flags: list[str], model_flagged: bool,
                history: dict[str, Any] | None, started: datetime, finished: datetime, profile: str = "embargoed",
                sandbox_isolation_class: str | None = None) -> tuple[list[dict[str, Any]], dict[str, Any], dict[str, Any] | None]:
        if profile not in ("published", "embargoed"):
            raise ValueError(f"unknown profile {profile!r}")
        isolation = sandbox_isolation_class or sandbox_isolation(sandbox_backend)
        sb_digest = sandbox_digest(sandbox_backend, isolation)
        models = [m.to_dict() for m in mbom]
        binding = {"harness": self.harness["digest"]["sha256"], "sandbox": sb_digest["sha256"],
                   "weights": [m["weights"]["digest"]["sha256"] for m in models if "digest" in m.get("weights", {})]}
        env = self.environment.evidence(self.enclave, binding) if self.enclave is not None else None
        rd = report_digest(sub)
        repo_url = f"git+https://github.com/{sub.repo}"
        # embargoed profile: the repository name is a digest too (provenance.md, Profiles), so the statement names no target
        subject = [{"name": f"finding:{rd[:4]}", "digest": {"sha256": rd}},
                   {"name": repo_url if profile == "published" else f"repo:sha256:{sha256_hex(repo_url.encode())}", "digest": {"gitCommit": revision}}]
        first = leaves[0] if leaves and leaves[0].get("kind") == "measure" else None
        r_started, r_finished = rerun.get("started_at") or started, rerun.get("finished_at") or finished
        reproduction: dict[str, Any] = {
            "test": {"digest": digest(repro.test_source)}, "expectedExit": 1, "observedExit": int(rerun["exit"]),
            "securityFailure": bool(rerun.get("security_failure")), "revision": revision, "executor": "code",
            "sandbox": {"backend": sandbox_backend, "isolation": isolation, "digest": sb_digest},
            "outputDigest": digest(rerun.get("output", "")), "startedAt": iso(r_started), "finishedAt": iso(r_finished)}
        if profile == "published":
            reproduction["test"]["path"] = repro.test_path
            reproduction["command"] = repro.command
        else:
            reproduction["commandDigest"] = digest(repro.command)
        pred: dict[str, Any] = {
            "vslaVersion": "1.0", "track": "finding", "claimedLevel": self._claimed(history, env, mbom), "profile": profile,
            "finder": self._finder(), "authorization": dict(self.authorization),
            "mbom": {"models": models, "tools": [{"name": "pytest"}]},
            "transcript": {"algorithm": "rfc6962-sha256", "root": merkle_root(leaf_bytes(leaves)), "leafCount": max(2, len(leaves)),
                           **({"firstLeaf": first} if first else {})},
            "reproduction": reproduction,
            "injection": {"scannerFlags": list(scanner_flags), "modelFlagged": bool(model_flagged)},
            "timestamps": {"startedAt": iso(started), "finishedAt": iso(finished)},
        }
        if self.channel:
            pred["channel"] = dict(self.channel)
        if history:
            pred["history"] = dict(history)
        if env:
            pred["environment"] = env
        return subject, pred, env

    # -- tracks

    def finding(self, **kw: Any) -> dict[str, Any]:
        subject, pred, env = self._common(**kw)
        return self._sign(subject, pred, env)

    def patch(self, *, patch: PatchResult, review: ReviewVerdict | None, reviewer_family: str | None = None, **kw: Any) -> dict[str, Any]:
        subject, pred, env = self._common(**kw)
        diff = patch.proposal.diff
        files = sorted(set(patch.proposal.files_touched) | set(diff_paths(diff)))
        pred["track"] = "patch"
        pred["patch"] = {"diffDigest": digest(diff), "scope": scope_of(files, diff), "applied": True,
                         "reproductionPasses": bool(patch.reproduction_passes), "suitePasses": bool(patch.suite_passes), "attempts": max(1, patch.attempts)}
        if pred["profile"] == "published":
            pred["patch"]["filesTouched"] = files
        else:
            pred["patch"]["filesTouchedDigest"] = digest(canonical(files))
        if review is not None:   # the finder's own review: informational (E8 needs the receiver's review in the receipt)
            pred["patch"]["review"] = {"approved": bool(review.approved), "reviewerRole": "reviewer", "verdictDigest": digest(review.model_dump_json()),
                                       **({"reviewerFamily": reviewer_family} if reviewer_family else {})}
        subject = [*subject, {"name": f"patch:{subject[0]['digest']['sha256'][:4]}", "digest": digest(diff)}]
        return self._sign(subject, pred, env)
