"""The case state machine. Speed is the SLO: reproduction starts the moment a report is acknowledged, in
parallel with triage; patching starts the moment a failing test exists; nothing waits for a human unless the
policy says so or someone calls pause. Every agent call is audited (inputs and outputs), every verification
is done by code (the model's claim that tests pass is never trusted), and every case ends in a postmortem.

VSLA (https://github.com/AAI-Society/vsla): qudisclose is a finder for every case it verifies (`_attest`) and the
platform for every statement a reporter submits (`_vsla_claimed` at intake, `_vsla_receipt` once a sandbox exists,
`_vsla_close` when the case ends). The platform never copies a finder's flag: it re-executes at the subject revision
with its own classifier, checks the test touched the subject, reviews a submitted patch on a different model family,
and signs what it found into a DSSE receipt, deferring under admission control rather than dropping a report."""

from __future__ import annotations

import hashlib
import logging
import os
import re
import shlex
import threading
import time
from collections import deque
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from qudisclose import __version__
from qudisclose.agents import (
    PatcherAgent, PostmortemAgent, Provider, ReleaseAgent, ReproducerAgent, ReviewerAgent, TriageAgent,
)
from qudisclose.config import Config, RepoConfig
from qudisclose.models import (
    Classification, Lane, PatchProposal, PatchResult, Postmortem, Report, ReproductionResult, SLOCheck,
    Severity, Status, now,
)
from qudisclose.publisher import LocalPublisher, Publisher
from qudisclose.security import AuditLog, CredentialBroker, Identity, InjectionScanner, SandboxBackend, make_sandbox
from qudisclose.security.sandbox import run_classified, sandbox_fault
from qudisclose.store import Store
from qudisclose.vsla import Attestor, Ledger, MBOMEntry, RecordingProvider, TranscriptRecorder, Verifier, make_receipt
from qudisclose.vsla.attest import diff_paths, harness_digest, iso, model_family, sandbox_digest, sandbox_isolation, scope_of
from qudisclose.vsla.canonical import canonical, digest
from qudisclose.vsla.dsse import envelope_payload, statement_digest
from qudisclose.vsla.environment import NoEnvironment, SignedQuoteEnvironment
from qudisclose.vsla.ledger import finder_id, ledger_root
from qudisclose.vsla.verify import vsla_keyring

log = logging.getLogger("qudisclose.orchestrator")

ACTOR = "orchestrator"


class CasePaused(Exception):
    pass


def _ts_or_none(v: Any) -> float | None:
    try:
        return datetime.fromisoformat(str(v).replace("Z", "+00:00")).timestamp()
    except (TypeError, ValueError):
        return None


def _try_root(entries: list[dict[str, Any]]) -> str | None:
    try:
        return ledger_root(entries)
    except (ValueError, TypeError, RecursionError):
        return None


class ConfigError(ValueError):
    """A deployment setting that makes the platform's VSLA claims untrue (e.g. an ephemeral platform key)."""


class Orchestrator:
    def __init__(self, *, store: Store, audit: AuditLog, config: Config, provider: Provider,
                 broker: CredentialBroker | None = None, publisher: Publisher | None = None,
                 clock: Callable[[], datetime] = now, platform_identity: Identity | None = None,
                 attestation_identity: Identity | None = None, reviewer_provider: Provider | None = None) -> None:
        self.store, self.audit, self.config = store, audit, config
        self.policy = config.policy
        vcfg = config.vsla
        # VSLA: every model turn and tool call becomes a transcript leaf; qudisclose signs statements as a finder
        # (attestation key) and countersigns receipts / ledger entries as the platform (server key).
        self.recorder = TranscriptRecorder()
        self.provider: Provider = RecordingProvider(provider, self.recorder, model_name=config.model)
        provider = self.provider
        if platform_identity is None:
            # VSLA-P-5/P-14: the platform key is what receipts, ledger entries and last-seen roots rest on. A key that
            # changes on every start makes every past receipt unverifiable, so refuse unless this is declared a demo.
            if vcfg.enabled and not vcfg.allow_ephemeral_platform_key:
                raise ConfigError("VSLA is enabled but no platform identity was supplied; load keys/server.json or set "
                                  "vsla.allow_ephemeral_platform_key=true for a demo (receipts signed by an ephemeral key verify nowhere)")
            platform_identity = Identity.generate("server")
        self.platform_identity = platform_identity
        self.attestation_identity = attestation_identity or Identity.generate("attestation")
        self.platform_name = config.public_url.split("//", 1)[-1].split("/", 1)[0]
        self.keyring = vsla_keyring(reporters=config.trusted_reporters, platform=self.platform_identity, platform_name=self.platform_name,
                                    roots=vcfg.trusted_roots, countersigners=vcfg.pinned_countersigners, providers=vcfg.trusted_providers,
                                    operators=vcfg.trusted_operators, logs=vcfg.trusted_logs)
        self.keyring.add(f"finder:{self.attestation_identity.name}", self.attestation_identity)   # the operator knows its own finder key out of band
        self.ledger = Ledger(store.db, self.platform_identity, platform_name=self.platform_name, keyring=self.keyring)
        environment = SignedQuoteEnvironment(vcfg.environment_evidence_path) if vcfg.environment_evidence_path else NoEnvironment()
        self.attestor = Attestor(finder=self.attestation_identity, operator=vcfg.operator or self.platform_name,
                                 channel={"intake": config.public_url, "intakeKey": f"ed25519:{self.platform_identity.public_hex}", "declaredIn": "policy"},
                                 environment=environment, enclave=self.attestation_identity if vcfg.environment_evidence_path else None,
                                 authorization={"basis": vcfg.authorization_basis, "ref": vcfg.authorization_ref},
                                 floor=vcfg.floor, min_entries=vcfg.min_entries, min_countersigners=vcfg.min_countersigners, min_age_days=vcfg.min_age_days)
        self.expectations = self._expectations()
        self.verifier = Verifier(self.keyring, platform_keyid=f"platform:{self.platform_name}", environment=environment, expectations=self.expectations,
                                 floor=vcfg.floor, min_entries=vcfg.min_entries, min_countersigners=vcfg.min_countersigners, min_age_days=vcfg.min_age_days,
                                 require_leaves=vcfg.require_leaves, require_anchor=vcfg.require_anchor, require_isolation=vcfg.require_isolation,
                                 accept_timestamp_anchor=vcfg.accept_timestamp_anchor)
        self.broker = broker or CredentialBroker(require_human_for=frozenset(
            {p for p, flag in (("pr:create", self.policy.require_human_for_merge), ("advisory:publish", self.policy.require_human_for_publish)) if flag}))
        self.publisher = publisher or LocalPublisher(config.out_dir)
        self.clock = clock
        self.scanner = InjectionScanner()
        # VSLA-P-10: the reviewer may run on a different provider/model family than the patcher.
        self._distinct_reviewer = reviewer_provider is not None
        self.reviewer_provider: Provider = RecordingProvider(reviewer_provider, self.recorder, model_name=config.inference.reviewer_model or config.model) \
            if reviewer_provider is not None else provider
        self.triage, self.reproducer, self.patcher = TriageAgent(provider), ReproducerAgent(provider), PatcherAgent(provider)
        self.reviewer, self.release, self.postmortem = ReviewerAgent(self.reviewer_provider), ReleaseAgent(provider), PostmortemAgent(provider)
        # VSLA-P-12: admission control for re-execution
        self._reexec_sem = threading.BoundedSemaphore(max(1, vcfg.reexec_concurrent))
        self._reexec_hist: dict[str, deque[float]] = {}
        self._admit_lock = threading.Lock()
        self._weights_cache: dict[tuple[str, int, int], str] = {}
        self._pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix="qud-case")
        self._stages = ThreadPoolExecutor(max_workers=8, thread_name_prefix="qud-stage")
        self._futures: dict[str, Any] = {}
        self._lock = threading.Lock()

    # ------------------------------------------------------------------ intake

    def intake(self, report: Report, actor: str = "intake") -> tuple[Report, bool]:
        """Dedup, scan, persist, acknowledge. Returns (report, is_new). Acknowledgement is immediate: SLO #1."""
        dup = self.store.find_duplicate(report)
        if dup:
            self.store.add_event(dup.id, "duplicate_received", actor, source=report.source, reporter=report.reporter.identity)
            self.audit.record(actor=actor, action="intake.duplicate", input={"content_hash": report.content_hash}, output={"duplicate_of": dup.id}, report_id=dup.id)
            if self.config.vsla.enabled and report.reporter.identity != dup.reporter.identity:
                # VSLA-P-6: a duplicate is a real bug someone else found first; it is countersigned as neutral, not held against the finder
                self.ledger.append(finder=self._finder_id(report), outcome="duplicate", report_id=dup.id, finder_key=report.reporter.public_key)
            return dup, False
        flags = self.scanner.scan(f"{report.submission.title}\n{report.submission.description}\n{report.submission.proof_of_concept or ''}").flags
        report.scanner_flags = flags
        if report.embargo_until and self.policy.embargo_days_max >= 0:
            report.embargo_until = min(report.embargo_until, self.policy.embargo_deadline(report.received_at))
        self.store.insert_report(report)
        self.store.add_event(report.id, "received", actor, source=report.source, reporter=report.reporter.identity, scanner_flags=flags)
        report.status = Status.ACKNOWLEDGED
        self.store.save_report(report)
        self.store.add_event(report.id, "acknowledged", ACTOR, embargo_until=report.embargo_until)
        self.audit.record(actor=actor, action="intake.accepted", input=report.submission.model_dump(exclude={"attestation"}),
                          output={"report_id": report.id, "scanner_flags": flags}, report_id=report.id)
        if self.config.vsla.enabled and report.submission.attestation:
            self._vsla_claimed(report, actor)
        return report, True

    def schedule(self, report_id: str) -> None:
        with self._lock:
            self._futures[report_id] = self._pool.submit(self._guarded_run, report_id)

    def wait(self, report_id: str, timeout: float | None = None) -> None:
        f = self._futures.get(report_id)
        if f is not None:
            f.result(timeout=timeout)

    def wait_all(self, timeout: float | None = None) -> None:
        for rid in list(self._futures):
            self.wait(rid, timeout)

    def _guarded_run(self, report_id: str) -> None:
        try:
            self.run_case(report_id)
        except Exception:  # pragma: no cover - logged, and the postmortem path inside run_case records it
            log.exception("case %s crashed", report_id)

    # ------------------------------------------------------------------ human controls

    def pause(self, report_id: str, actor: str, reason: str = "") -> Report:
        r = self._must(report_id)
        self.store.set_paused(report_id, True)
        r.paused = True
        self.store.add_event(report_id, "paused", actor, reason=reason)
        self.audit.record(actor=actor, action="case.pause", input={"reason": reason}, output={"status": r.status}, report_id=report_id)
        return r

    def resume(self, report_id: str, actor: str) -> Report:
        r = self._must(report_id)
        self.store.set_paused(report_id, False)
        r.paused = False
        if r.status == Status.PAUSED:
            r.status = Status.ACKNOWLEDGED
            self.store.save_report(r)
        self.store.add_event(report_id, "resumed", actor)
        self.audit.record(actor=actor, action="case.resume", input={}, output={"status": r.status}, report_id=report_id)
        self.schedule(report_id)
        return r

    def approve_release(self, report_id: str, actor: str) -> Report:
        r = self._must(report_id)
        self.broker.approve_human("pr:create", r.submission.repo)
        self.broker.approve_human("advisory:publish", r.submission.repo)
        self.store.add_event(report_id, "human_approved_release", actor)
        self.audit.record(actor=actor, action="case.approve_release", input={}, output={}, report_id=report_id)
        if r.status == Status.RELEASING:
            self.schedule(report_id)
        return r

    # ------------------------------------------------------------------ pipeline

    def run_case(self, report_id: str) -> Report:
        report = self._must(report_id)
        if report.paused:
            return report
        if report.status in (Status.CLOSED, Status.REJECTED):
            return report
        sandbox: SandboxBackend | None = None
        reproduced = False
        rerun: dict[str, Any] | None = None
        try:
            if report.status == Status.RELEASING:
                return self._release_and_close(report)
            repo_cfg = self._repo_cfg(report)
            self._transition(report, Status.TRIAGING)
            started = self.clock()
            # VSLA-F-14: leaf 0 is the measurement, before any model turn can land on this case's transcript.
            self.recorder.forget(report.id)
            self.recorder.measure(report.id, harness=self.attestor.harness["digest"], sandbox=self._sandbox_digest())
            # Speculative: reproduction runs in parallel with triage.
            triage_f = self._stages.submit(self._audited, "triage", report.id, lambda: self.triage.run(report, self._known_titles(report)))
            sandbox = make_sandbox(report.id, repo_path=repo_cfg.path, config=self.config.sandbox)
            sandbox.create()
            revision = sandbox.revision()          # VSLA-F-2: the subject revision is the baseline, before any test is added
            if self.config.vsla.enabled and report.submission.attestation:
                self._vsla_receipt(report, repo_cfg)   # VSLA-P-3/P-4: re-execute the finder's reproduction in our own sandbox, sign the receipt
            repro_f = self._stages.submit(self._audited, "reproducer", report.id, lambda: self.reproducer.run(report, sandbox)) \
                if self.policy.speculative_patching else None

            triage = triage_f.result()
            self.store.put_artifact(report.id, "triage", triage)
            report.severity, report.lane = triage.severity, triage.lane
            if triage.injection_suspected and "model_flagged_injection" not in report.scanner_flags:
                report.scanner_flags.append("model_flagged_injection")
            if (report.vsla.get("submitted") or {}).get("deferred") and report.lane == Lane.HOTFIX:
                report.lane = Lane.SCHEDULED       # VSLA-P-12: a deferred re-execution routes the case to the slow lane, never drops it
                self.store.add_event(report.id, "slow_lane", ACTOR, reason="re-execution deferred by admission control")
            self.store.save_report(report)
            self.store.add_event(report.id, "triage_done", "triage", severity=triage.severity, lane=triage.lane, cvss=triage.cvss_score, cwe=triage.cwe,
                                 duplicate_of=triage.duplicate_of, injection_suspected=triage.injection_suspected)
            if not triage.is_vulnerability or triage.lane == Lane.REJECT:
                if repro_f:
                    repro_f.cancel()
                return self._finish(report, Status.REJECTED, "rejected_by_triage", sandbox)

            self._checkpoint(report)
            self._transition(report, Status.REPRODUCING)
            repro: ReproductionResult = repro_f.result() if repro_f else self._audited("reproducer", report.id, lambda: self.reproducer.run(report, sandbox))
            self.store.put_artifact(report.id, "reproduction", repro)
            self.store.add_event(report.id, "reproduction_done", "reproducer", fails_on_vulnerable=repro.fails_on_vulnerable, test_path=repro.test_path)
            # Never trust the agent's claim: re-run the failing test ourselves on the vulnerable tree, with the normative classifier.
            rerun = self._rerun(sandbox, repro)
            self.recorder.verify(report.id, what="reproduction", command=repro.command, exit_code=rerun["exit"],
                                 security_failure=rerun["security_failure"], output=rerun["output"])
            if not repro.fails_on_vulnerable or not rerun["ok"]:
                self.store.add_event(report.id, "reproduction_unverified", ACTOR, exit=rerun["exit"], reason=rerun["reason"], timed_out=rerun["timed_out"])
                return self._finish(report, Status.FAILED, "could_not_reproduce", sandbox, detail={"rerun": rerun})
            reproduced = True
            sandbox.commit("qudisclose: reproduction test")  # the patcher's diff must cover only the fix
            if self.config.vsla.enabled:
                self._attest(report, "finding", repro=repro, rerun=rerun, revision=revision, triage=triage, started=started)

            self._checkpoint(report)
            self._transition(report, Status.PATCHING)
            patch = self._patch_loop(report, repo_cfg, repro, sandbox)
            if patch is None:
                return self._finish(report, Status.FAILED, "no_verified_patch", sandbox, detail={"reproduced": True})
            self.store.put_artifact(report.id, "patch", patch)

            self._checkpoint(report)
            self._transition(report, Status.REVIEWING)
            verdict = self._audited("reviewer", report.id, lambda: self.reviewer.run(report, patch))
            self.store.put_artifact(report.id, "review", verdict)
            self.store.add_event(report.id, "review_done", "reviewer", approved=verdict.approved, required_changes=verdict.required_changes, suspicious=verdict.suspicious,
                                 reviewer_family=self._reviewer_entry().family, distinct_family=self._distinct_reviewer)
            rounds = 0
            while not verdict.approved and rounds < self.policy.max_patch_attempts:
                rounds += 1
                patch = self._patch_loop(report, repo_cfg, repro, sandbox, feedback=verdict.required_changes + verdict.suspicious)
                if patch is None:
                    return self._finish(report, Status.FAILED, "no_verified_patch_after_review", sandbox, detail={"reproduced": True})
                self.store.put_artifact(report.id, "patch", patch)
                verdict = self._audited("reviewer", report.id, lambda: self.reviewer.run(report, patch))
                self.store.put_artifact(report.id, "review", verdict)
                self.store.add_event(report.id, "review_done", "reviewer", approved=verdict.approved, required_changes=verdict.required_changes, round=rounds)
            if not verdict.approved:
                return self._finish(report, Status.FAILED, "review_rejected", sandbox, detail={"reproduced": True})
            if self.config.vsla.enabled:
                self._attest(report, "patch", repro=repro, rerun=rerun, revision=revision, triage=triage, started=started, patch=patch, review=verdict)

            self._checkpoint(report)
            self._transition(report, Status.RELEASING)
            plan = self._audited("release", report.id, lambda: self.release.run(
                report, triage, patch, self._current_version(sandbox), advisory_id=f"QUD-{report.received_at:%Y}-{report.id[-6:].upper()}"))
            self.store.put_artifact(report.id, "release_plan", plan)
            self.store.add_event(report.id, "release_plan_ready", "release", new_version=plan.new_version)
            sandbox.destroy(); sandbox = None
            return self._release_and_close(report)
        except CasePaused:
            report = self._must(report.id)
            report.status = Status.PAUSED
            self.store.save_report(report)
            return report
        except Exception as exc:
            log.exception("case %s failed", report.id)
            self.store.add_event(report.id, "error", ACTOR, error=repr(exc)[:500])
            return self._finish(report, Status.FAILED, f"exception: {type(exc).__name__}", sandbox, detail={"reproduced": reproduced})
        finally:
            if sandbox is not None:
                sandbox.destroy()

    # ------------------------------------------------------------------ stages

    def _patch_loop(self, report: Report, repo_cfg: RepoConfig, repro: ReproductionResult, sandbox: SandboxBackend,
                    feedback: list[str] | None = None) -> PatchResult | None:
        fb = list(feedback or [])
        last_out = ""
        for attempt in range(1, self.policy.max_patch_attempts + 1):
            self._checkpoint(report)
            proposal = self._audited("patcher", report.id, lambda: self.patcher.run(report, sandbox, repro, fb or None))
            proposal = self._authoritative_diff(sandbox, proposal)
            result = self._verify_patch(report, repo_cfg, repro, proposal, attempt)
            self.store.add_event(report.id, "patch_attempt", "patcher", attempt=attempt, reproduction_passes=result.reproduction_passes,
                                 suite_passes=result.suite_passes, files=proposal.files_touched, scope=scope_of(proposal.files_touched))
            if result.reproduction_passes and result.suite_passes:
                self.store.add_event(report.id, "patch_verified", ACTOR, attempt=attempt)
                return result
            last_out = result.output_excerpt
            fb = [f"Attempt {attempt} failed verification. reproduction_passes={result.reproduction_passes} suite_passes={result.suite_passes}.",
                  f"Output:\n{last_out[-2500:]}"]
            # reset the working sandbox for the next attempt
            sandbox.destroy(); sandbox.create(); sandbox.write(repro.test_path, repro.test_source); sandbox.commit("qudisclose: reproduction test")
        return None

    def _authoritative_diff(self, sandbox: SandboxBackend, proposal: PatchProposal) -> PatchProposal:
        """Trust the git-generated diff of the patcher's OWN sandbox edits over the model's hand-written
        `diff`. Models (even strong ones) routinely emit unified diffs with drifted context/line numbers
        that `git apply` rejects, so every independent verification fails regardless of the fix's quality.
        The patcher edits the sandbox via tools and is told to return `current_diff` (= `sandbox.diff()`);
        here we make that authoritative. If the model returned only diff text without editing the sandbox,
        we realize it there first, then capture the canonical, guaranteed-appliable diff."""
        if not sandbox.diff().strip() and proposal.diff.strip():
            sandbox.apply_diff(proposal.diff)
        captured = sandbox.diff()
        if not captured.strip():
            return proposal
        touched = sorted({ln[6:] for ln in captured.splitlines() if ln.startswith("+++ b/")})
        return proposal.model_copy(update={"diff": captured, "files_touched": touched or proposal.files_touched})

    def _verify_patch(self, report: Report, repo_cfg: RepoConfig, repro: ReproductionResult, proposal: Any, attempt: int) -> PatchResult:
        """Independent verification in a clean worktree: apply diff, run the reproduction test, run the suite."""
        clean = make_sandbox(f"{report.id}-verify", repo_path=repo_cfg.path, config=self.config.sandbox)
        clean.create()
        try:
            applied = clean.apply_diff(proposal.diff) if proposal.diff.strip() else None
            if applied is None or applied.returncode != 0:
                return PatchResult(proposal=proposal, reproduction_passes=False, suite_passes=False, attempts=attempt,
                                   output_excerpt=("empty diff" if applied is None else f"diff did not apply:\n{applied.excerpt()}")[-4000:])
            clean.write(repro.test_path, repro.test_source)  # after apply: the diff may legitimately not include the test
            r1 = clean.run(shlex.split(repro.command))
            r2 = clean.run(shlex.split(repo_cfg.test_command))
            files = {}
            for path in proposal.files_touched:
                try:
                    files[path] = clean.read(path)
                except Exception:
                    pass
            res = PatchResult(proposal=proposal, reproduction_passes=r1.ok, suite_passes=r2.ok, attempts=attempt,
                              output_excerpt=(f"[reproduction] {r1.excerpt(1500)}\n[suite] {r2.excerpt(2000)}")[-4000:])
            object.__setattr__(res, "_files", files)
            return res
        finally:
            clean.destroy()

    def _rerun(self, sandbox: SandboxBackend, repro: ReproductionResult, *, subject: str | None = None,
               extra_files: list[str] | None = None) -> dict[str, Any]:
        """Code-side re-run of the reproduction with the normative VSLA-F-5 classifier (security/sandbox.py). `ok` only
        when a collected test failed by assertion with no collection/import/fixture error and exit 1. With `subject`
        the run is traced so the receipt can say whether the test touched the package the report names (VSLA-P-4)."""
        sandbox.write(repro.test_path, repro.test_source)
        started = self.clock()
        r, c = run_classified(sandbox, repro.command, subject=subject, extra_files=extra_files)
        finished = self.clock()
        sec = c.security_failure and r.returncode == 1 and not r.timed_out
        fault = sandbox_fault(sandbox) if c.collected == 0 and not r.timed_out else None
        return {"ok": sec, "exit": r.returncode, "timed_out": r.timed_out, "security_failure": sec, "reason": c.reason,
                "output": r.excerpt(), "started_at": started, "finished_at": finished, "classification": c.to_dict(),
                "touched_subject": c.touched_subject, "touched_method": c.touched_method, "touched_means": c.touched_means,
                "sandbox_fault": fault}

    def _test_fails(self, sandbox: SandboxBackend, repro: ReproductionResult) -> bool:
        return self._rerun(sandbox, repro)["ok"]

    def _release_and_close(self, report: Report) -> Report:
        plan_d = self.store.get_artifact(report.id, "release_plan")
        patch_d = self.store.get_artifact(report.id, "patch")
        from qudisclose.models import ReleasePlan
        plan, patch = ReleasePlan.model_validate(plan_d), PatchResult.model_validate(patch_d)
        try:
            self._checkpoint(report)
            arts = self.store.artifacts(report.id)
            attestations: dict[str, Any] = {}
            for track in ("finding", "patch"):
                emb, pub = arts.get(f"vsla_{track}"), arts.get(f"vsla_{track}_published")
                if pub:
                    attestations[track] = pub            # the case is becoming public: the plaintext profile goes beside the advisory
                    if emb:
                        attestations[f"{track}-embargoed"] = emb
                elif emb:
                    attestations[track] = emb
            if arts.get("vsla_receipt"):
                attestations["receipt"] = arts["vsla_receipt"]
            import inspect
            params = inspect.signature(self.publisher.publish).parameters
            extra = {"attestations": attestations or None} if ("attestations" in params or any(p.kind is p.VAR_KEYWORD for p in params.values())) else {}
            result = self.publisher.publish(report, plan, patch, holder=f"release-agent:{report.id}", **extra)
        except PermissionError as exc:
            self.store.add_event(report.id, "awaiting_human_approval", ACTOR, reason=str(exc))
            self.audit.record(actor=ACTOR, action="release.blocked", input={}, output={"reason": str(exc)}, report_id=report.id)
            return report
        self.store.add_event(report.id, "published", "release", pr_url=result.pr_url, advisory_url=result.advisory_url)
        self.audit.record(actor="release", action="release.published", input={"version": plan.new_version}, output=result.__dict__, report_id=report.id)
        report.classification = Classification.PUBLIC
        report.embargo_until = self.clock()
        self._transition(report, Status.PUBLISHED)
        return self._finish(report, Status.CLOSED, "published", None)

    def _finish(self, report: Report, status: Status, outcome: str, sandbox: SandboxBackend | None, detail: dict[str, Any] | None = None) -> Report:
        if sandbox is not None:
            sandbox.destroy()
        report = self._must(report.id)
        report.status = status
        self.store.save_report(report)
        self.store.add_event(report.id, "finished", ACTOR, status=status, outcome=outcome)
        checks = self.slo_checks(report)
        try:
            pm = self._audited("postmortem", report.id, lambda: self.postmortem.run(
                report, self.store.events(report.id), checks, self.store.artifacts(report.id), outcome))
        except Exception as exc:  # the postmortem must never be the reason a case has no record
            pm = Postmortem(report_id=report.id, outcome=outcome, timeline=[e.kind for e in self.store.events(report.id)], slo_checks=checks,
                            went_well=[], went_badly=[f"postmortem agent failed: {exc!r}"], action_items=["fix postmortem agent"], summary="auto-generated fallback")
        self.store.put_artifact(report.id, "postmortem", pm)
        self.store.add_event(report.id, "postmortem_written", "postmortem", slo_missed=[c.name for c in checks if c.met is False])
        if self.config.vsla.enabled:
            self._vsla_close(report, outcome, detail or {})
        self.recorder.forget(report.id)
        return report

    # ------------------------------------------------------------------ VSLA: finder role

    def _sandbox_digest(self) -> dict[str, str]:
        return sandbox_digest(self.config.sandbox.backend, sandbox_isolation(self.config.sandbox.backend))

    def _expectations(self) -> dict[str, Any]:
        """VSLA-V-6: what this platform independently expects. It knows its own harness digest (so it can verify
        statements produced by the same qudisclose version) plus whatever `vsla.expectations_path` adds."""
        exp: dict[str, Any] = {"harness": {"qudisclose": {__version__: harness_digest()["sha256"]}}, "measurements": []}
        path = self.config.vsla.expectations_path
        if path and Path(path).exists():
            import json
            extra = json.loads(Path(path).read_text())
            for name, versions in (extra.get("harness") or {}).items():
                exp["harness"].setdefault(name, {}).update(versions)
            exp["measurements"].extend(extra.get("measurements") or [])
        return exp

    def _weights(self) -> tuple[str | None, bool]:
        """(sha256 of the loaded weight file, unmeasured): the digest only when `inference.weights_path` names a file.
        Cached by (path, size, mtime). The model's name is never hashed (VSLA-F-3)."""
        path = self.config.inference.weights_path
        if not path or not os.path.isfile(path):
            return None, True
        st = os.stat(path)
        key = (path, st.st_size, int(st.st_mtime))
        if key not in self._weights_cache:
            h = hashlib.sha256()
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(1 << 20), b""):
                    h.update(chunk)
            self._weights_cache[key] = h.hexdigest()
        return self._weights_cache[key], False

    def _entry(self, role: str, provider: str, model: str) -> MBOMEntry:
        if provider == "scripted":
            return MBOMEntry(role=role, provider="qudisclose", name="scripted", family="scripted", serving="api", version=__version__)
        if provider in ("anthropic", "claude"):
            return MBOMEntry(role=role, provider="anthropic", name=model, family="claude", serving="api")
        fam = model_family(provider, model)
        wd, unmeasured = self._weights()
        return MBOMEntry(role=role, provider=fam, name=model, family=fam, serving="self-hosted", weights_digest=wd, weights_unmeasured=unmeasured)

    def _reviewer_entry(self) -> MBOMEntry:
        inf = self.config.inference
        if self._distinct_reviewer:
            return self._entry("reviewer", inf.reviewer_provider or "local", inf.reviewer_model or inf.model)
        cfg = self.config
        return self._entry("reviewer", cfg.provider, cfg.inference.model if cfg.provider in ("local", "openai") else cfg.model)

    def _mbom(self) -> list[MBOMEntry]:
        """VSLA-F-3: every model that produced or filtered content on the path to the finding, with family and serving mode."""
        cfg = self.config
        roles = ("triage", "reproducer", "patcher", "release", "postmortem")
        model = cfg.inference.model if cfg.provider in ("local", "openai") else cfg.model
        return [self._entry(r, cfg.provider, model) for r in roles] + [self._reviewer_entry()]

    def _attest(self, report: Report, track: str, *, repro: ReproductionResult, rerun: dict[str, Any], revision: str, triage: Any,
                started: datetime, patch: PatchResult | None = None, review: Any = None) -> None:
        """Emit and store qudisclose's own VSLA statement for this case (finder role) in both profiles: the embargoed one
        is what the platform exposes while the case is open, the published one goes beside the advisory. Never blocks the pipeline."""
        try:
            leaves = self.recorder.leaves(report.id)
            kw: dict[str, Any] = dict(sub=report.submission, leaves=leaves, mbom=self._mbom(), repro=repro, rerun=rerun,
                                      revision=revision, sandbox_backend=self.config.sandbox.backend, scanner_flags=report.scanner_flags,
                                      model_flagged=bool(getattr(triage, "injection_suspected", False)),
                                      history=self.ledger.summary(f"ed25519:{self.attestation_identity.public_hex}", floor=self.config.vsla.floor, track=track),
                                      started=started, finished=self.clock())
            if track == "finding":
                emb, pub = (self.attestor.finding(profile=p, **kw) for p in ("embargoed", "published"))
            else:
                fam = self._reviewer_entry().family
                emb, pub = (self.attestor.patch(patch=patch, review=review, reviewer_family=fam, profile=p, **kw) for p in ("embargoed", "published"))  # type: ignore[arg-type]
            claimed = envelope_payload(emb)["predicate"]["claimedLevel"]
            self.store.put_artifact(report.id, f"vsla_{track}", emb)
            self.store.put_artifact(report.id, f"vsla_{track}_published", pub)
            self.store.put_artifact(report.id, "vsla_leaves", leaves)
            report.vsla = {**report.vsla, track: {"claimed": claimed, "statement": statement_digest(emb), "published_statement": statement_digest(pub),
                                                   "profile": "embargoed", "leaves": len(leaves)}}
            self.store.save_report(report)
            self.store.add_event(report.id, "vsla_attested", ACTOR, track=track, claimed=claimed, statement=statement_digest(emb))
            self.audit.record(actor=ACTOR, action=f"vsla.attest.{track}", input={"revision": revision},
                              output={"claimed": claimed, "statement": statement_digest(emb), "published_statement": statement_digest(pub)}, report_id=report.id)
        except Exception as exc:  # pragma: no cover - attestation must never be why a case fails
            log.exception("vsla attestation failed for %s", report.id)
            self.store.add_event(report.id, "vsla_attest_failed", ACTOR, track=track, error=repr(exc)[:300])

    # ------------------------------------------------------------------ VSLA: platform role

    def _vsla_claimed(self, report: Report, actor: str) -> None:
        """Intake-time verification of a submitted statement (VSLA-P-1/P-2): everything except our own re-execution,
        which happens in run_case. Records the claim and the preliminary verified level; never trusts the claim."""
        bundle = report.submission.attestation or {}
        res = self._verify_bundle(report, bundle, reexecution=None)
        report.vsla = {**report.vsla, "submitted": {"claimed": res.claimed, "verified": res.verified, "track": res.track, "stage": "intake",
                                                    "pillars": res.to_dict()["pillars"], "statement": statement_digest(bundle["statement"]) if "statement" in bundle else None}}
        self.store.save_report(report)
        self.store.add_event(report.id, "vsla_claimed", ACTOR, track=res.track, claimed=res.claimed, verified_preliminary=res.verified,
                             failed={k: v.failed for k, v in res.pillars.items() if v.failed})
        self.audit.record(actor=actor, action="vsla.verify", input={"stage": "intake"}, output=res.to_dict(), report_id=report.id)

    def _verify_bundle(self, report: Report, bundle: dict[str, Any], *, reexecution: dict[str, Any] | None,
                       receipt: dict[str, Any] | None = None) -> Any:
        """Run the verifier over a submitted bundle with everything this platform holds: the finder's key as pinned at the
        MCP boundary, the ledger the finder handed over (never a summary), and the last root this platform stored for it."""
        if report.reporter.public_key and not self.keyring.has(f"finder:{report.reporter.identity}"):
            # the MCP boundary already verified this key; pin it, but never overwrite a pinned entry (it may carry a validity window)
            self.keyring.add(f"finder:{report.reporter.identity}", report.reporter.public_key)
        ledger_entries = self._presented_ledger(report)
        fid, track = self._finder_id(report), self._track(report)
        try:
            return self.verifier.verify(bundle.get("statement", {}), report=report.submission, leaves=bundle.get("leaves"), receipt=receipt,
                                        reexecution=reexecution, ledger_entries=ledger_entries, last_seen=self.ledger.last_seen(fid, track),
                                        required_entries=self._required_entries(report, fid, track), expected_intake=self.config.public_url)
        except Exception as exc:  # a malformed bundle is an L0 report, never a crashed case
            log.warning("vsla bundle unreadable for %s: %r", report.id, exc)
            return self.verifier.verify({}, report=report.submission)

    @staticmethod
    def _presented_ledger(report: Report) -> list[dict[str, Any]] | None:
        bundle = report.submission.attestation or {}
        return bundle.get("ledger") if isinstance(bundle.get("ledger"), list) else None

    @staticmethod
    def _track(report: Report) -> str:
        bundle = report.submission.attestation or {}
        try:
            return str(envelope_payload(bundle["statement"])["predicate"].get("track") or "finding")
        except Exception:
            return "finding"

    @staticmethod
    def _finder_id(report: Report) -> str:
        """The ledger key for this reporter: its Ed25519 key when the MCP boundary verified one, else its name (VSLA-F-8)."""
        return finder_id(report.reporter.identity, report.reporter.public_key)

    def finder_id(self, identity: str, public_key: str | None = None) -> str:
        """Resolve a reporter name to its ledger key: the signer key when given, else the pinned reporter key, else the name."""
        return finder_id(identity, public_key or self.config.trusted_reporters.get(identity))

    def _required_entries(self, report: Report, fid: str, track: str) -> list[dict[str, Any]]:
        """VSLA-P-14: the entries this platform countersigned for `(finder, track)` that the presented ledger must include:
        only those written before this statement was received, so an honest second case submitted while the first was
        still open (whose ledger could not yet contain the first case's entry) is not a fork."""
        cutoff = report.received_at.timestamp()
        out = []
        for e in self.ledger.own_entries(fid, track):
            at = _ts_or_none((envelope_payload(e) or {}).get("at"))
            if at is not None and at <= cutoff:
                out.append(e)
        return out

    def _verified_presented(self, report: Report) -> int:
        """How many NON-NEUTRAL presented outcome entries verify under a pinned countersigner for this finder's key chain,
        on any track (VSLA-V-5, P-12): a free `duplicate` does not make an identity known."""
        presented = self._presented_ledger(report)
        if not presented:
            return 0
        from qudisclose.vsla.ledger import successor_chain, verified_ledger
        from qudisclose.vsla.rubric import NEUTRAL
        finder = f"ed25519:{report.reporter.public_key}" if report.reporter.public_key else None
        chain = successor_chain(presented, finder) if finder else None
        return sum(1 for b in verified_ledger(presented, self.keyring, finder=chain)[0] if b.get("outcome") not in NEUTRAL)

    def _admit(self, identity: str, verified_presented: int = 0) -> tuple[bool, str]:
        """VSLA-P-12: bound re-execution per identity and globally. False means defer (not-attempted receipt, slow lane). An
        *unknown* identity is one whose submission presents no ledger entry that verifies under a countersigner this
        platform pins; by default it is deferred to the slow lane rather than handed a sandbox."""
        vcfg = self.config.vsla
        if not vcfg.reexec_unknown_identities and verified_presented == 0:
            return False, "identity presents no ledger entry verifiable under a pinned countersigner and reexec_unknown_identities is off"
        now_s = time.time()
        with self._admit_lock:
            hist = self._reexec_hist.setdefault(identity, deque())
            while hist and now_s - hist[0] > 3600:
                hist.popleft()
            if len(hist) >= vcfg.reexec_per_identity_per_hour:
                return False, f"per-identity limit of {vcfg.reexec_per_identity_per_hour} re-executions per hour reached"
            if not self._reexec_sem.acquire(blocking=False):
                return False, f"concurrency limit of {vcfg.reexec_concurrent} re-executions reached"
            hist.append(now_s)
        return True, "admitted"

    def _vsla_receipt(self, report: Report, repo_cfg: RepoConfig) -> None:
        """VSLA-P-3/P-4: re-execute the finder's reproduction at the subject revision in a clean sandbox we control (and,
        for a Patch statement, apply the diff, run the reproduction and the suite, compute the scope and review it on a
        distinct model family), sign the receipt, record the verified level. A receipt is issued in every case."""
        bundle = report.submission.attestation or {}
        if self.store.get_artifact(report.id, "vsla_receipt") is not None:
            # a resumed or re-acknowledged case: the receipt was signed once, on receipt; it is not re-executed or overwritten
            self.store.add_event(report.id, "vsla_receipt_exists", ACTOR)
            return
        try:
            stmt = envelope_payload(bundle["statement"])
            pred, subj = stmt["predicate"], stmt.get("subject", [])
        except Exception:
            pred, subj = {}, []
        track = str(pred.get("track") or "finding")
        revision = str(subj[1].get("digest", {}).get("gitCommit") or "") if len(subj) > 1 else ""
        rp = bundle.get("reproduction") or {}
        identity = report.reporter.identity
        admitted, why = self._admit(identity, self._verified_presented(report))
        reexec: dict[str, Any] = {"status": "not-attempted"}
        deferred = False
        try:
            if not admitted:
                reexec["reason"] = f"admission control: {why}"
                deferred = True
            elif not (rp.get("test_source") and rp.get("test_path") and rp.get("command")):
                reexec["reason"] = "bundle carries no reproduction body (reproduction.test_path, test_source, command)"
            elif not revision:
                reexec["reason"] = "statement names no subject revision"
            else:
                reexec = self._reexecute(report, repo_cfg, pred, track, revision, rp, bundle)
        except Exception as exc:
            log.exception("re-execution failed for %s", report.id)
            reexec = {**reexec, "status": "environment-error", "reason": f"platform error: {type(exc).__name__}"}
        finally:
            if admitted:
                self._reexec_sem.release()
        if deferred:
            self.store.add_event(report.id, "vsla_reexec_deferred", ACTOR, reason=why)
        receipt = make_receipt(bundle["statement"], platform=self.platform_identity, keyid=self.ledger.keyid, channel=self.config.public_url,
                               received_at=iso(report.received_at), reexecution=reexec)
        res = self._verify_bundle(report, bundle, reexecution=reexec, receipt=receipt)
        # VSLA-P-14: remember the ledger root this statement carried (what we were SHOWN, per finder key and track), or record
        # the fork. The verifier already checked the prefix root and that every entry this platform countersigned is included.
        ledger_entries = self._presented_ledger(report)
        fid = self._finder_id(report)
        ledger_ok = False
        if ledger_entries is not None:
            i4 = res.detail("I4")
            root = _try_root(ledger_entries)
            if i4.startswith("ledger-fork"):
                reason = ("presented ledger omits an entry this platform countersigned (VSLA-P-14)" if "omits" in i4
                          else "presented ledger does not extend the one this platform was shown last time (VSLA-P-14)")
                self.ledger.append(finder=fid, outcome="ledger-fork", track=track, report_id=report.id, statement_digest=statement_digest(bundle["statement"]),
                                   finder_key=report.reporter.public_key, reason=reason)
                self.store.add_event(report.id, "vsla_ledger_fork", ACTOR, finder=identity, reason=reason)
            elif root is not None and root == (pred.get("history") or {}).get("root"):
                self.ledger.remember(fid, track, root, len(ledger_entries))
                ledger_ok = True
        self.store.put_artifact(report.id, "vsla_receipt", receipt)
        self.store.put_artifact(report.id, "vsla_verification", res.to_dict())
        report.vsla = {**report.vsla, "submitted": {**report.vsla.get("submitted", {}), "verified": res.verified, "stage": "reexecuted",
                                                    "pillars": res.to_dict()["pillars"], "reexecution": reexec.get("status"), "deferred": deferred,
                                                    "reexecuted": reexec.get("status") not in (None, "not-attempted"), "ledger_ok": ledger_ok}}
        self.store.save_report(report)
        self.store.add_event(report.id, "vsla_verified", ACTOR, track=res.track, claimed=res.claimed, verified=res.verified, reexecution=reexec.get("status"),
                             failed={k: v.failed for k, v in res.pillars.items() if v.failed})
        self.audit.record(actor=ACTOR, action="vsla.verify", input={"stage": "reexecuted", "reexecution": reexec}, output=res.to_dict(), report_id=report.id)

    def _reexecute(self, report: Report, repo_cfg: RepoConfig, pred: dict[str, Any], track: str, revision: str,
                   rp: dict[str, Any], bundle: dict[str, Any]) -> dict[str, Any]:
        """The platform's own re-execution (VSLA-P-4), in a clean sandbox at the subject revision."""
        backend = self.config.sandbox.backend
        isolation = sandbox_isolation(backend)
        command, test_source, test_path = str(rp["command"]), str(rp["test_source"]), str(rp["test_path"])
        out: dict[str, Any] = {"status": "environment-error", "revision": revision, "testDigest": digest(test_source),
                               "sandbox": {"backend": backend, "isolation": isolation, "digest": sandbox_digest(backend, isolation)}, "attempts": 1}
        if "commandDigest" in (pred.get("reproduction") or {}):
            out["commandDigest"] = digest(command)          # the receipt echoes the embargoed form (provenance.md, Profiles)
        else:
            out["command"] = command
        clean = make_sandbox(f"{report.id}-reexec", repo_path=repo_cfg.path, config=self.config.sandbox)
        if hasattr(clean, "isolation_detail"):
            out["sandbox"]["detail"] = clean.isolation_detail()    # what `process` isolation meant on this host (netfilter, rlimits)
        clean.create()
        try:
            if not clean.checkout(revision):
                return {**out, "reason": f"revision {revision[:12]} is not available in the platform's checkout of {report.submission.repo}"}
            repro = ReproductionResult(test_path=test_path, test_source=test_source, fails_on_vulnerable=True, command=command, output_excerpt="")
            # the subject package is the PLATFORM's name for it (repo config), never a field of the finder's report
            subject = repo_cfg.package or report.submission.repo.split("/")[-1]
            diff = str((bundle.get("patch") or {}).get("diff") or "") if track == "patch" else ""
            r = self._rerun(clean, repro, subject=subject, extra_files=diff_paths(diff) if diff else None)
            self.recorder.verify(report.id, what="reexecution", command=command, exit_code=r["exit"], security_failure=r["security_failure"], output=r["output"])
            out.update(observedExit=int(r["exit"]), securityFailure=bool(r["security_failure"]), touchedSubject=bool(r["touched_subject"]),
                       touchedSubjectMethod=r["touched_method"], touchedSubjectMeans=r["touched_means"], touchedSubjectPackage=subject,
                       outputDigest=digest(r["output"]), classifier=r["classification"])
            if r["timed_out"]:
                return {**out, "status": "timeout"}
            if r["sandbox_fault"]:
                return {**out, "status": "environment-error", "reason": r["sandbox_fault"]}
            expected = int((pred.get("reproduction") or {}).get("observedExit", 1))
            if track != "patch":
                return {**out, "status": "matched" if r["exit"] == expected else "mismatched"}
            # Patch track: the three executions in the clean checkout, the scope, and our own review (VSLA-P-10, F-18)
            if not diff:
                return {**out, "status": "mismatched", "applied": False, "reproductionPasses": False, "suitePasses": False, "reason": "bundle carries no patch.diff"}
            applied = clean.apply_diff(diff)
            out["applied"] = applied.returncode == 0
            if not out["applied"]:
                return {**out, "status": "mismatched", "reproductionPasses": False, "suitePasses": False, "reason": f"diff did not apply: {applied.excerpt(300)}"}
            clean.write(test_path, test_source)
            r1 = clean.run(shlex.split(command))
            r2 = clean.run(shlex.split(repo_cfg.test_command))
            files = diff_paths(diff)
            out.update(reproductionPasses=r1.ok, suitePasses=r2.ok, scope=scope_of(files, diff))
            out["review"] = self._platform_review(report, pred, diff, files, r1.ok, r2.ok, (f"[reproduction] {r1.excerpt(1500)}\n[suite] {r2.excerpt(2000)}")[-4000:])
            if r1.timed_out or r2.timed_out:
                return {**out, "status": "timeout"}
            return {**out, "status": "matched" if (r1.ok and r2.ok) else "mismatched"}
        finally:
            clean.destroy()

    def _platform_review(self, report: Report, pred: dict[str, Any], diff: str, files: list[str], repro_ok: bool, suite_ok: bool, output: str) -> dict[str, Any]:
        """VSLA-P-10: the platform's own adversarial review of a submitted patch, over the diff and test output only, on a
        reviewer whose family must differ from every patcher in the finder's MBOM. `distinctFamily` is reported honestly."""
        entry = self._reviewer_entry()
        models = (pred.get("mbom") or {}).get("models") or []
        patchers = {m.get("family") or model_family(str(m.get("provider", "")), str(m.get("name", ""))) for m in models if "patch" in str(m.get("role", "")).lower()}
        if not patchers:
            patchers = {m.get("family") or model_family(str(m.get("provider", "")), str(m.get("name", ""))) for m in models}
        distinct = bool(patchers) and entry.family not in patchers
        proposal = PatchProposal(summary="(submitted patch)", diff=diff, files_touched=files, risk_notes="")
        pr = PatchResult(proposal=proposal, reproduction_passes=repro_ok, suite_passes=suite_ok, attempts=1, output_excerpt=output)
        try:
            verdict = self._audited("reviewer", report.id, lambda: self.reviewer.run(report, pr))
            approved, vd = bool(verdict.approved), digest(verdict.model_dump_json())
        except Exception as exc:
            approved, vd = False, digest(f"review failed: {type(exc).__name__}")
        return {"approved": approved, "reviewerFamily": entry.family or "unknown", "distinctFamily": distinct, "verdictDigest": vd}

    def _vsla_close(self, report: Report, outcome: str, detail: dict[str, Any]) -> None:
        """VSLA-P-6/P-15: countersign the outcome into the reporter's ledger when the case closes, per track.
        `accepted` only when the disclosure's outcome was accepted (published/merged); a finding reproduced but not
        resolved is `reproduced-unresolved`; negatives carry a reason; failures the platform caused get no entry."""
        sub = report.vsla.get("submitted") or {}
        rx = (self.store.get_artifact(report.id, "vsla_receipt") or {})
        rx_body = envelope_payload(rx).get("reexecution", {}) if rx else {}
        rx_ran = rx_body.get("status") in ("matched", "mismatched")        # the platform did execute the FINDER's test at the subject revision
        fid = self._finder_id(report)
        # claimed/verified go into the countersigned entry only when the platform actually re-executed, or when the statement
        # failed on its own terms (L0: signature, subject, schema; VSLA-P-2); a deferred (not-attempted) submission whose
        # verified level is 1 only because E7 could not run is not an over-claim (round 3)
        judged = rx_ran or sub.get("verified") == 0
        common: dict[str, Any] = dict(finder=fid, report_id=report.id, statement_digest=sub.get("statement"), finder_key=report.reporter.public_key,
                                      **({"claimed": sub.get("claimed"), "verified": sub.get("verified")} if judged else {}))
        reproduced = bool(detail.get("reproduced")) or self.store.get_artifact(report.id, "vsla_finding") is not None
        submitted = bool(report.submission.attestation)
        submitted_patch = sub.get("track") == "patch"
        entries: list[tuple[str, str, str | None]] = []   # (track, outcome, reason)
        skip_reason: str | None = None
        if outcome == "published":
            entries.append(("finding", "accepted", None))
            if submitted_patch:
                patch_ok = rx_body.get("status") == "matched" and (rx_body.get("review") or {}).get("approved") is True
                entries.append(("patch", "accepted" if patch_ok else "reproduced-unresolved", None if patch_ok else "the platform shipped its own fix; the submitted patch did not pass re-execution and review"))
        elif outcome == "rejected_by_triage":
            tri = self.store.get_artifact(report.id, "triage") or {}
            rationale = str(tri.get("rationale") or "no rationale recorded").strip()
            entries.append(("finding", "rejected", f"triage ({digest(canonical(tri))['sha256'][:16]}): {rationale[:300]}"))
        elif outcome == "could_not_reproduce":
            rr = detail.get("rerun") or {}
            cls = rr.get("classification") or {}
            if submitted:
                # The outcome follows the platform's re-execution of the FINDER's test (the receipt), never the platform's own
                # reproducer agent, whose failure is the platform's, not the finder's.
                if not rx_ran:
                    skip_reason = f"the platform did not execute the finder's reproduction (receipt status {rx_body.get('status')!r}); no outcome recorded"
                elif rx_body.get("securityFailure") is True:
                    entries.append(("finding", "reproduced-unresolved", None))
                else:
                    why = (rx_body.get("classifier") or {}).get("reason") or "not an assertion failure in a collected test"
                    entries.append(("finding", "false-positive", f"the finder's reproduction did not fail by assertion at the subject revision: {why}"))
            elif rr.get("timed_out") or rr.get("sandbox_fault") or cls.get("errors") or rr.get("exit") not in (0, 1):
                skip_reason = f"reproduction could not be executed in the platform sandbox ({rr.get('sandbox_fault') or rr.get('reason')}); no outcome recorded"
            else:
                entries.append(("finding", "false-positive", f"reproduction did not fail by assertion on the vulnerable tree: {rr.get('reason')}"))
        elif reproduced:
            entries.append(("finding", "reproduced-unresolved", None))
            if submitted_patch:
                entries.append(("patch", "reproduced-unresolved", None))
        else:
            skip_reason = f"case ended before reproduction ({outcome}); no outcome recorded"
        if skip_reason:
            self.store.add_event(report.id, "vsla_ledger_skipped", ACTOR, finder=report.reporter.identity, reason=skip_reason)
            report.vsla = {**report.vsla, "ledger": {"outcome": None, "skipped": skip_reason}}
            self.store.save_report(report)
            return
        outcomes: dict[str, str] = {}
        for track, o, reason in entries:
            # each entry goes into the ledger of its own track; the finder appends it where its log is at (no seq), and
            # must include it next time it presents that track's ledger here (VSLA-P-14)
            env = self.ledger.append(track=track, outcome=o, reason=reason, **common)
            outcomes[track] = o
            self.store.add_event(report.id, "vsla_ledger_appended", ACTOR, finder=report.reporter.identity, track=track, outcome=o,
                                 countersigner=env["signatures"][0]["keyid"])
        report.vsla = {**report.vsla, "ledger": {"outcome": outcomes.get("finding"), "outcomes": outcomes,
                                                 "scores": {t: self.ledger.score(fid, t)["score"] for t in ("finding", "patch")},
                                                 "score": self.ledger.score(fid, "finding")["score"]}}
        self.store.save_report(report)

    # ------------------------------------------------------------------ SLOs

    def slo_checks(self, report: Report) -> list[SLOCheck]:
        events = self.store.events(report.id)
        t0 = report.received_at

        def first(kind: str, **match: Any) -> datetime | None:
            for e in events:
                if e.kind == kind and all(e.data.get(k) == v for k, v in match.items()):
                    return e.at
            return None

        def mins(t: datetime | None) -> float | None:
            return None if t is None else round((t - t0).total_seconds() / 60, 2)

        slo = self.policy.slo
        rows = [("acknowledge", slo.acknowledge, mins(first("acknowledged"))),
                ("triage", slo.triage, mins(first("triage_done"))),
                (f"patch_{(report.severity or Severity.MEDIUM)}", slo.patch_target(report.severity), mins(first("patch_verified"))),
                ("review", slo.review, None if first("patch_verified") is None or first("review_done", approved=True) is None else
                 round((first("review_done", approved=True) - first("patch_verified")).total_seconds() / 60, 2)),
                ("publish_after_fix", slo.publish_after_fix, None if first("review_done", approved=True) is None or first("published") is None else
                 round((first("published") - first("review_done", approved=True)).total_seconds() / 60, 2))]
        done = report.status in (Status.CLOSED, Status.REJECTED, Status.FAILED, Status.PUBLISHED)
        out = []
        for name, target, actual in rows:
            if actual is None:
                met = False if (done and report.status != Status.REJECTED and name not in ("acknowledge",)) else None
                if report.status == Status.REJECTED and name in ("acknowledge", "triage"):
                    met = None
            else:
                met = actual <= target
            out.append(SLOCheck(name=name, target_minutes=target, actual_minutes=actual, met=met))
        return out

    # ------------------------------------------------------------------ helpers

    def _audited(self, role: str, report_id: str, fn: Callable[[], Any]) -> Any:
        try:
            with self.recorder.case(report_id):
                out = fn()
        except Exception as exc:
            self.audit.record(actor=f"agent:{role}", action=f"{role}.error", input={}, output={"error": repr(exc)[:500]}, report_id=report_id)
            raise
        self.audit.record(actor=f"agent:{role}", action=f"{role}.result", input={"report_id": report_id},
                          output=out.model_dump() if hasattr(out, "model_dump") else out, report_id=report_id)
        return out

    def _transition(self, report: Report, status: Status) -> None:
        report.status = status
        self.store.save_report(report)
        self.store.add_event(report.id, "status", ACTOR, status=status)

    def _checkpoint(self, report: Report) -> None:
        if self.store.is_paused(report.id):
            raise CasePaused(report.id)

    def _must(self, report_id: str) -> Report:
        r = self.store.get_report(report_id)
        if r is None:
            raise KeyError(report_id)
        return r

    def _repo_cfg(self, report: Report) -> RepoConfig:
        cfg = self.config.repos.get(report.submission.repo)
        if cfg is None:
            raise KeyError(f"repository {report.submission.repo} is not configured for automated patching")
        return cfg

    def _known_titles(self, report: Report) -> list[str]:
        return [f"{r.id}: {r.submission.title}" for r in self.store.list_reports() if r.id != report.id and r.status not in (Status.REJECTED,)][:50]

    @staticmethod
    def _current_version(sandbox: SandboxBackend) -> str:
        for rel in ("pyproject.toml", "package.json", "VERSION", "Cargo.toml"):
            try:
                text = sandbox.read(rel)
            except Exception:
                continue
            m = re.search(r'"?version"?\s*[:=]\s*"([^"]+)"', text) or re.match(r"\s*(\d+\.\d+\.\d+\S*)\s*$", text)
            if m:
                return m.group(1)
        return "0.0.0"
