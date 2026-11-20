"""VSLA in qudisclose (spec v1.0, revision 3): statements on both tracks and in both profiles for every verified case,
verification of submitted statements with re-execution at the subject revision, the platform's own classifier, coverage,
review and scope, DSSE receipts, the countersigned DSSE ledger with last-seen roots, admission control, and the MCP / CLI
surface. Requirement ids refer to https://github.com/AAI-Society/vsla/blob/main/spec/v1.0/requirements.md."""

import base64
import json
import shutil
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from mcp import Client
from mcp.shared.exceptions import MCPError

from qudisclose.config import Config, RepoConfig
from qudisclose.demo import FIXTURE, demo_provider, demo_submission
from qudisclose.models import Lane, Report, Reporter, ReportSubmission, Source, Status
from qudisclose.orchestrator import ConfigError, Orchestrator
from qudisclose.publisher import LocalPublisher
from qudisclose.security import AuditLog, Identity
from qudisclose.security.keys import KeyRing
from qudisclose.security.sandbox import LocalSandbox, run_classified
from qudisclose.server import build_server
from qudisclose.store import Store
from qudisclose.vsla import Attestor, Keyring, MBOMEntry, canonical, merkle_root, verify_receipt, verify_signature
from qudisclose.vsla.attest import model_family, scope_of
from qudisclose.vsla.dsse import RECEIPT_PAYLOAD_TYPE, envelope_payload, make_weights_attestation, statement_digest
from qudisclose.vsla.environment import make_signed_quote
from qudisclose.vsla.ledger import ledger_root, make_ledger_entry
from qudisclose.vsla.merkle import inclusion_proof, leaf_bytes, verify_inclusion
from tests.conftest import new_report

# ----------------------------------------------------------------------------- helpers (also used by test_vsla_interop)

def _platform(tmp_path, repo, name, *, url="http://127.0.0.1:8765/mcp", countersigners=None, reviewer_provider=None, **vsla):
    """A qudisclose deployment with its own platform and finder keys. `countersigners` = [(keyid, Identity)] it pins."""
    cfg = Config(db_dsn=":memory:", out_dir=str(tmp_path / f"out-{name}"), provider="scripted", public_url=url,
                 repos={"example/vulnpkg": RepoConfig(path=str(repo), test_command="python -m pytest -q")})
    cfg.vsla.pinned_countersigners = {kid: k.public_hex for kid, k in (countersigners or [])}
    for k, v in vsla.items():
        setattr(cfg.vsla, k, v)
    if reviewer_provider is not None:
        cfg.inference.reviewer_provider, cfg.inference.reviewer_model = "local", "qwen3.8:27b"
    store = Store(":memory:")
    audit = AuditLog(store.db, Identity.generate("audit"))
    orch = Orchestrator(store=store, audit=audit, config=cfg, provider=demo_provider(), publisher=LocalPublisher(cfg.out_dir),
                        platform_identity=Identity.generate("server"), attestation_identity=Identity.generate(f"qudisclose@{name}"),
                        reviewer_provider=reviewer_provider)
    return cfg, store, orch


def _countersigners():
    return [("maintainer:example/libparse", Identity.generate("maintainer:example/libparse")), ("platform:cvd.other.org", Identity.generate("platform:cvd.other.org"))]


def _fid(forch):
    """The ledger id of a finder deployment: its attestation key (the ledger is keyed by key and track, never by name)."""
    return f"ed25519:{forch.attestation_identity.public_hex}"


def _seed_ledger(orch, finder, countersigners, n=5, *, finder_key=None, days=100, outcome="accepted", track="finding"):
    """Entries other platforms/maintainers countersigned for `finder`, as the finder keeps them; imported into `orch`'s mirror."""
    out = []
    for i in range(n):
        kid, key = countersigners[i % len(countersigners)]
        body = {"at": (datetime.now(UTC) - timedelta(days=days - i)).isoformat(timespec="seconds").replace("+00:00", "Z"),
                "finder": f"ed25519:{finder_key}" if finder_key else finder, "statement": {"sha256": "%064x" % (i + 1)}, "platform": kid.split(":", 1)[1],
                "track": track, "outcome": outcome, "claimed": 1, "verified": 1}
        if outcome in ("rejected", "false-positive"):
            body["reason"] = "seeded"
        env = make_ledger_entry(body, [(kid, key)])
        assert orch.ledger.import_entry(finder, env), kid
        out.append(env)
    return out


def _finder_bundle(tmp_path, repo, platform_orch, *, with_history=True, track="finding", countersigners=None, repo_path=None, url="http://127.0.0.1:8765/mcp"):
    """A finder deployment runs the case itself and hands over {statement, leaves, reproduction, patch?, ledger} for the platform.
    `url` is the finder's own intake (its platform keyid derives from it; give it a distinct host when the test needs the finder
    to pin the receiving platform's key too)."""
    cs = countersigners or _countersigners()
    fcfg, fstore, forch = _platform(tmp_path, repo_path or repo, "finder", countersigners=cs, url=url)
    forch.attestor.channel = {"intake": platform_orch.config.public_url, "intakeKey": f"ed25519:{platform_orch.platform_identity.public_hex}", "declaredIn": "policy"}
    if with_history:
        _seed_ledger(forch, _fid(forch), cs, finder_key=forch.attestation_identity.public_hex, track=track)
        for kid, k in cs:                       # the receiving platform pins the same countersigners
            platform_orch.keyring.add(kid, k)
    rep, _ = forch.intake(new_report(), actor="agent:researcher-1")
    forch.run_case(rep.id)
    arts = fstore.artifacts(rep.id)
    repro = arts["reproduction"]
    stmt = arts[f"vsla_{track}"]
    n = envelope_payload(stmt)["predicate"]["transcript"]["leafCount"]
    bundle = {"statement": stmt, "leaves": arts["vsla_leaves"][:n],
              "reproduction": {"test_path": repro["test_path"], "test_source": repro["test_source"], "command": repro["command"]},
              "ledger": forch.ledger.entries(_fid(forch), track)}
    if track == "patch":
        bundle["patch"] = {"diff": arts["patch"]["proposal"]["diff"]}
    return forch, bundle, cs


def _submit(orch, forch, bundle, *, identity=None):
    sub = ReportSubmission(**{**demo_submission().model_dump(), "attestation": bundle})
    rep = Report.from_submission(sub, source=Source.MCP, reporter=Reporter(identity=identity or forch.attestation_identity.name, public_key=forch.attestation_identity.public_hex))
    rep, is_new = orch.intake(rep, actor=forch.attestation_identity.name)
    assert is_new
    return rep


def _triage_ok():
    from qudisclose.demo import _triage
    return _triage("", {})


# ----------------------------------------------------------------------------- finder role: every verified case is attested

def test_pipeline_emits_finding_and_patch_statements_in_both_profiles(env):
    """VSLA-F-1..F-7, F-18, F-19: both tracks, both profiles, signed by the deployment's finder key, transcript-rooted with a
    measured leaf 0 and a matching verify leaf, reproduction by code at the baseline revision, scope computed from the diff."""
    cfg, store, audit, provider, orch = env
    rep, _ = orch.intake(new_report(), actor="agent:researcher-1")
    r = orch.run_case(rep.id)
    assert r.status == Status.CLOSED
    arts = store.artifacts(rep.id)
    assert {"vsla_finding", "vsla_patch", "vsla_finding_published", "vsla_patch_published", "vsla_leaves"} <= set(arts)
    finding, patch, leaves = arts["vsla_finding"], arts["vsla_patch"], arts["vsla_leaves"]
    pf, pp = envelope_payload(finding)["predicate"], envelope_payload(patch)["predicate"]
    assert pf["track"] == "finding" and pp["track"] == "patch" and pf["claimedLevel"] == 1 and pp["claimedLevel"] == 1
    assert pf["profile"] == "embargoed" and "commandDigest" in pf["reproduction"] and "command" not in pf["reproduction"] and "path" not in pf["reproduction"]["test"]
    pub = envelope_payload(arts["vsla_finding_published"])["predicate"]
    assert pub["profile"] == "published" and pub["reproduction"]["command"] == "python -m pytest -q tests/test_qud_path_traversal.py" and pub["reproduction"]["test"]["path"]
    assert pf["authorization"] == {"basis": "ownership"}
    assert pf["reproduction"]["executor"] == "code" and pf["reproduction"]["observedExit"] == 1 and pf["reproduction"]["securityFailure"] is True
    assert pf["reproduction"]["sandbox"] == {"backend": "local", "isolation": "process", "digest": pf["reproduction"]["sandbox"]["digest"]}
    assert pf["reproduction"]["startedAt"] >= pf["timestamps"]["startedAt"] and pf["reproduction"]["finishedAt"] <= pf["timestamps"]["finishedAt"]
    # VSLA-F-2: the subject revision is the fixture's commit, not a commit that includes the reproduction test
    head = subprocess.run(["git", "-C", cfg.repos["example/vulnpkg"].path, "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
    assert envelope_payload(finding)["subject"][1]["digest"]["gitCommit"] == head == pf["reproduction"]["revision"]
    # Patch track: scope from the diff, files as a digest in the embargoed profile, the finder's review carries no `independent`
    assert pp["patch"]["applied"] and pp["patch"]["reproductionPasses"] and pp["patch"]["suitePasses"] and pp["patch"]["scope"] == "source-only"
    assert "filesTouchedDigest" in pp["patch"] and "filesTouched" not in pp["patch"] and "independent" not in pp["patch"]["review"]
    assert envelope_payload(arts["vsla_patch_published"])["predicate"]["patch"]["filesTouched"] == ["vulnpkg/files.py"]
    # MBOM: every role plus the reviewer, with a family; the scripted provider is declared as what it is
    assert {m["role"] for m in pf["mbom"]["models"]} == {"triage", "reproducer", "patcher", "release", "postmortem", "reviewer"}
    assert all(m["family"] == "scripted" and m["serving"] == "api" for m in pf["mbom"]["models"])
    # VSLA-F-4: leaf 0 measures; a verify leaf agrees with the reproduction section; the root commits to the leaves in order
    assert leaves[0]["kind"] == "measure" and leaves[0]["harness"] == pf["finder"]["harness"]["digest"] and leaves[0]["sandbox"] == pf["reproduction"]["sandbox"]["digest"]
    kinds = [x["kind"] for x in leaves]
    assert "turn" in kinds and "tool" in kinds and "verify" in kinds
    vleaf = next(x for x in leaves if x["kind"] == "verify" and x["what"] == "reproduction")
    assert vleaf["exit"] == 1 and vleaf["securityFailure"] is True and vleaf["output"] == pf["reproduction"]["outputDigest"]
    assert merkle_root(leaf_bytes(leaves[:pf["transcript"]["leafCount"]])) == pf["transcript"]["root"]
    assert merkle_root(leaf_bytes(leaves[:pp["transcript"]["leafCount"]])) == pp["transcript"]["root"]
    assert pp["transcript"]["leafCount"] > pf["transcript"]["leafCount"]
    fk = Identity(f"finder:{orch.attestation_identity.name}", None, orch.attestation_identity.public_key)
    assert verify_signature(finding, fk.name, fk) and verify_signature(patch, fk.name, fk)
    # verification with our own re-execution evidence at the subject revision: Evidence L2, Environment L2 (own harness expectation),
    # Identity L1 (no receipt, no ledger) -> verified L1
    orch.keyring.add(fk.name, fk)
    rx = {"status": "matched", "revision": head, "observedExit": 1, "securityFailure": True, "touchedSubject": True, "outputDigest": {"sha256": "0" * 64}}
    res = orch.verifier.verify(finding, report=rep.submission, leaves=leaves[:pf["transcript"]["leafCount"]], reexecution=rx, expected_intake=cfg.public_url)
    assert res.claimed == 1 and res.verified == 1 and res.pillars["evidence"].level >= 2 and res.pillars["environment"].level == 2 \
        and res.pillars["identity"].failed == "I3", res.to_dict()
    assert {c["id"]: c["kind"] for c in res.to_dict()["checks"]}["E1"] == "structural" and {c["id"]: c["kind"] for c in res.to_dict()["checks"]}["E2"] == "external"
    # published beside the advisory in both profiles; the reporter's outcome is countersigned into the ledger (VSLA-P-6)
    out = Path(cfg.out_dir) / rep.id
    assert {p.name for p in out.glob("vsla.*.json")} >= {"vsla.finding.json", "vsla.finding-embargoed.json", "vsla.patch.json", "vsla.patch-embargoed.json"}
    assert envelope_payload(json.loads((out / "vsla.finding.json").read_text()))["predicate"]["profile"] == "published"
    assert r.vsla["finding"]["claimed"] == 1 and r.vsla["ledger"]["outcome"] == "accepted" and r.vsla["ledger"]["outcomes"] == {"finding": "accepted"}
    ents = orch.ledger.entries(orch.finder_id("agent:researcher-1", r.reporter.public_key))
    assert len(ents) == 1 and ents[0]["payloadType"] == "application/vnd.vsla.ledger-entry+json" and orch.ledger.verify_entry(ents[0])
    body = envelope_payload(ents[0])
    assert body["outcome"] == "accepted" and body["kind"] == "outcome" and "seq" not in body and body["track"] == "finding"
    assert "vsla_attested" in [e.kind for e in store.events(rep.id)] and "vsla_ledger_appended" in [e.kind for e in store.events(rep.id)]
    ok, msg = audit.verify_chain()
    assert ok, msg


def test_rejected_and_unreproducible_outcomes_land_in_ledger_with_reasons(env):
    """VSLA-P-6/P-15: negative outcomes carry a reason; a failure the platform's own environment caused records nothing."""
    cfg, store, audit, provider, orch = env
    provider.scripts["triage"] = lambda user, tools: {**_triage_ok(), "is_vulnerability": False, "lane": "reject"}
    rep, _ = orch.intake(new_report(), actor="agent:researcher-1")
    r = orch.run_case(rep.id)
    assert r.status == Status.REJECTED and r.vsla["ledger"]["outcome"] == "rejected"
    assert envelope_payload(orch.ledger.entries("agent:researcher-1")[0])["reason"].startswith("triage")
    assert "vsla_finding" not in store.artifacts(rep.id)
    # a test that passes on the vulnerable tree: false-positive, with the classifier's reason
    cfg2, store2, orch2 = _platform(Path(cfg.out_dir).parent, Path(cfg.repos["example/vulnpkg"].path), "fp")
    passing = "def test_nothing():\n    assert True\n"
    orch2.provider.inner.scripts["reproducer"] = lambda u, t: (t["write_file"]("tests/test_fp.py", passing), dict(
        test_path="tests/test_fp.py", test_source=passing, fails_on_vulnerable=True, command="python -m pytest -q tests/test_fp.py", output_excerpt=""))[-1]
    rep2, _ = orch2.intake(new_report(), actor="agent:researcher-1")
    r2 = orch2.run_case(rep2.id)
    assert r2.status == Status.FAILED and r2.vsla["ledger"]["outcome"] == "false-positive"
    assert "no assertion failure" in envelope_payload(orch2.ledger.entries("agent:researcher-1")[0])["reason"]
    # a test that cannot be collected: the platform could not execute it, so no outcome is written against the finder
    cfg3, store3, orch3 = _platform(Path(cfg.out_dir).parent, Path(cfg.repos["example/vulnpkg"].path), "env")
    broken = "import does_not_exist\n\ndef test_x():\n    assert False\n"
    orch3.provider.inner.scripts["reproducer"] = lambda u, t: (t["write_file"]("tests/test_broken.py", broken), dict(
        test_path="tests/test_broken.py", test_source=broken, fails_on_vulnerable=True, command="python -m pytest -q tests/test_broken.py", output_excerpt=""))[-1]
    rep3, _ = orch3.intake(new_report(), actor="agent:researcher-1")
    r3 = orch3.run_case(rep3.id)
    assert r3.status == Status.FAILED and r3.vsla["ledger"]["outcome"] is None and orch3.ledger.entries("agent:researcher-1") == []
    assert "vsla_ledger_skipped" in [e.kind for e in store3.events(rep3.id)]


def test_inclusion_proof_lets_a_finder_reveal_one_leaf(env):
    cfg, store, audit, provider, orch = env
    rep, _ = orch.intake(new_report(), actor="agent:researcher-1")
    orch.run_case(rep.id)
    leaves = store.artifacts(rep.id)["vsla_leaves"]
    root = envelope_payload(store.artifacts(rep.id)["vsla_patch"])["predicate"]["transcript"]["root"]
    lb = leaf_bytes(leaves)
    i = next(i for i, x in enumerate(leaves) if x["kind"] == "verify")
    assert verify_inclusion(lb[i], inclusion_proof(lb, i), root)
    tampered = dict(leaves[i]); tampered["exit"] = 0
    assert not verify_inclusion(canonical(tampered), inclusion_proof(lb, i), root)


def test_mbom_weights_are_measured_or_unmeasured_never_the_model_name(env, tmp_path):
    """VSLA-F-3: a self-hosted model carries the digest of the loaded weight file when `inference.weights_path` names one,
    else `unmeasured: true`; the model name is never hashed. Families drive reviewer diversity."""
    cfg, store, audit, provider, orch = env
    cfg.provider = "local"; cfg.inference.model = "qwen3.8:27b"
    models = [m.to_dict() for m in orch._mbom()]
    assert all(m["serving"] == "self-hosted" and m["weights"] == {"unmeasured": True} and m["family"] == "qwen" and m["provider"] == "qwen" for m in models)
    w = tmp_path / "weights.gguf"; w.write_bytes(b"\x00" * 4096)
    cfg.inference.weights_path = str(w)
    import hashlib
    models = [m.to_dict() for m in orch._mbom()]
    assert all(m["weights"]["digest"]["sha256"] == hashlib.sha256(b"\x00" * 4096).hexdigest() for m in models)
    assert all(m["weights"]["digest"]["sha256"] != hashlib.sha256(b"unattested:qwen3.8:27b").hexdigest() for m in models)
    cfg.provider = "anthropic"
    assert all(m["family"] == "claude" and m["serving"] == "api" and "weights" not in m for m in (m.to_dict() for m in orch._mbom()))
    assert model_family("anthropic", "claude-opus-5-5") == "claude" and model_family("local", "glm-4.6") == "glm" and model_family("local", "llama3.1:70b") == "llama"
    assert scope_of(["vulnpkg/files.py"]) == "source-only" and scope_of(["vulnpkg/files.py", "pyproject.toml"]) == "mixed" \
        and scope_of([".github/workflows/ci.yml"]) == "mixed" and scope_of(["tests/fixtures/blob.bin"]) == "mixed"


# ----------------------------------------------------------------------------- the normative classifier (VSLA-F-5)

def _classify(repo, test_source, command="python -m pytest -q tests/test_c.py", *, subject=None):
    sb = LocalSandbox(repo, case_id="classify")
    sb.create()
    try:
        sb.write("tests/test_c.py", test_source)
        return run_classified(sb, command, subject=subject)
    finally:
        sb.destroy()


def test_classifier_accepts_only_assertion_failures_in_collected_tests(repo):
    """VSLA-F-5: `assert`, `AssertionError` from the code under test and pytest `Failed` (DID NOT RAISE) count; a collection
    error, a bare sys.exit(1), a NameError and a passing test do not; a non-pytest command is never classified True."""
    r, c = _classify(repo, "from vulnpkg import resolve_path\n\ndef test_x(tmp_path):\n    assert '..' not in str(resolve_path(tmp_path, '../x'))\n", subject="vulnpkg")
    assert r.returncode == 1 and c.security_failure and c.collected == 1 and c.assertion_failures == 1 and c.errors == 0, c
    assert c.touched_subject is True and c.touched_method in ("importtime", "coverage") and "vulnpkg" in " ".join(c.imported)
    r, c = _classify(repo, "import pytest\nfrom vulnpkg import resolve_path\n\ndef test_x(tmp_path):\n    with pytest.raises(ValueError):\n        resolve_path(tmp_path, '../x')\n")
    assert c.security_failure and c.assertion_failures == 1, c
    r, c = _classify(repo, "import missing_module_zzz\n\ndef test_x():\n    assert False\n")          # collection error: no assert ever ran
    assert not c.security_failure and c.errors >= 1 and c.collected == 0 and "collection" in c.reason, c
    r, c = _classify(repo, "import sys\n\ndef test_x():\n    sys.exit(1)\n")                           # exit 1 without an assertion
    assert r.returncode == 1 and not c.security_failure and c.failures == 1 and c.assertion_failures == 0, c
    r, c = _classify(repo, "def test_x():\n    undefined_symbol(1)\n")                                  # NameError at runtime
    assert not c.security_failure and c.assertion_failures == 0, c
    r, c = _classify(repo, "def test_x():\n    assert True\n")
    assert r.returncode == 0 and not c.security_failure and c.collected == 1 and c.failures == 0, c
    r, c = _classify(repo, "def test_x():\n    assert False\n", command="python -c 'import sys; sys.exit(1)'")
    assert not c.security_failure and c.classifier == "none" and "pytest only" in c.reason
    r, c = _classify(repo, "def test_x():\n    assert False\n", subject="vulnpkg")                       # never touches the subject
    assert c.security_failure and c.touched_subject is False


# ----------------------------------------------------------------------------- platform role: submitted statements

def test_submitted_statement_is_reexecuted_at_revision_receipted_and_verified_l2(tmp_path, repo):
    """VSLA-P-1..P-4, P-14, V-4/V-5: a Finding L2 claim from a finder whose handed-over ledger is countersigned by two pinned
    keys verifies at L2 after our own re-execution at the subject revision with our own classifier and coverage check."""
    cfg, store, orch = _platform(tmp_path, repo, "platform")
    forch, bundle, cs = _finder_bundle(tmp_path, repo, orch)
    assert envelope_payload(bundle["statement"])["predicate"]["claimedLevel"] == 2
    rep = _submit(orch, forch, bundle)
    assert rep.vsla["submitted"]["claimed"] == 2 and rep.vsla["submitted"]["stage"] == "intake" and rep.vsla["submitted"]["verified"] == 1  # no receipt yet
    r = orch.run_case(rep.id)
    assert r.status == Status.CLOSED
    kinds = [e.kind for e in store.events(rep.id)]
    assert kinds.index("vsla_claimed") < kinds.index("vsla_verified") < kinds.index("vsla_attested")
    ver = store.get_artifact(rep.id, "vsla_verification")
    assert ver["claimed"] == 2 and ver["verified"] == 2, ver
    assert r.vsla["submitted"]["reexecution"] == "matched" and r.vsla["submitted"]["verified"] == 2
    receipt = store.get_artifact(rep.id, "vsla_receipt")
    assert receipt["payloadType"] == RECEIPT_PAYLOAD_TYPE and receipt["signatures"][0]["keyid"] == f"platform:{orch.platform_name}"
    assert verify_receipt(receipt, orch.ledger.keyid, orch.platform_identity)
    body = envelope_payload(receipt)
    assert body["vslaVersion"] == "1.0" and body["statementDigest"] == statement_digest(bundle["statement"]) and body["channel"] == cfg.public_url
    rx = body["reexecution"]
    assert rx["status"] == "matched" and rx["revision"] == envelope_payload(bundle["statement"])["subject"][1]["digest"]["gitCommit"]
    assert rx["observedExit"] == 1 and rx["securityFailure"] is True and rx["touchedSubject"] is True and rx["touchedSubjectMethod"] in ("importtime", "coverage")
    assert rx["sandbox"]["backend"] == "local" and rx["sandbox"]["isolation"] == "process" and "digest" in rx["sandbox"] and rx["attempts"] == 1
    assert rx["sandbox"]["detail"]["netns"] in ("unshare", "sandbox-exec", "none") and rx["touchedSubjectMeans"] in ("imported", "covered") and rx["touchedSubjectPackage"] == "vulnpkg"
    assert "commandDigest" in rx and "command" not in rx         # the receipt echoes the embargoed form
    # VSLA-P-14: the platform stores what it was SHOWN per (key, track) and separately the entry it wrote, which must be
    # included (anywhere) in the finder's next ledger; no index is assigned by the platform (round 3)
    own = orch.ledger.own_entries(_fid(forch), "finding")
    assert len(own) == 1 and "seq" not in envelope_payload(own[0])
    assert orch.ledger.last_seen(_fid(forch), "finding") == (ledger_root(bundle["ledger"]), len(bundle["ledger"]))
    assert (Path(cfg.out_dir) / rep.id / "vsla.receipt.json").exists()
    last = envelope_payload(orch.ledger.entries(_fid(forch))[-1])
    assert last["outcome"] == "accepted" and last["claimed"] == 2 and last["verified"] == 2 and last["statement"]["sha256"] == statement_digest(bundle["statement"])
    assert last["finder"] == f"ed25519:{forch.attestation_identity.public_hex}" and last["track"] == "finding"


def test_self_reported_history_fails_i4(tmp_path, repo):
    """VSLA-V-3/F-11: a statement whose history summary meets the floor but comes without the ledger entries stays at L1."""
    cfg, store, orch = _platform(tmp_path, repo, "platform")
    forch, bundle, cs = _finder_bundle(tmp_path, repo, orch)
    bundle.pop("ledger")
    assert envelope_payload(bundle["statement"])["predicate"]["history"]["score"] >= 0.6
    rep = _submit(orch, forch, bundle)
    r = orch.run_case(rep.id)
    ver = store.get_artifact(rep.id, "vsla_verification")
    assert ver["claimed"] == 2 and ver["verified"] == 1 and ver["pillars"]["identity"]["failed"] == "I4"
    assert "ledger not supplied" in next(c["detail"] for c in ver["checks"] if c["id"] == "I4")
    assert orch.ledger.last_seen(_fid(forch), "finding") is None


def test_unverifiable_ledger_signatures_are_dropped(tmp_path, repo):
    """VSLA-V-5: entries countersigned by keys this platform has not pinned count toward neither n nor m."""
    cfg, store, orch = _platform(tmp_path, repo, "platform")
    forch, bundle, cs = _finder_bundle(tmp_path, repo, orch)
    for kid, _ in cs:                                            # un-pin the countersigners on the receiving side
        orch.keyring._keys.pop(kid); orch.ledger.keyring._keys.pop(kid, None)
    rep = _submit(orch, forch, bundle)
    orch.run_case(rep.id)
    ver = store.get_artifact(rep.id, "vsla_verification")
    i4 = next(c for c in ver["checks"] if c["id"] == "I4")
    assert ver["verified"] == 1 and ver["pillars"]["identity"]["failed"] == "I4" and "5 outcome entries dropped" in i4["detail"] and "below floor" in i4["detail"]
    # forged signatures are dropped the same way
    bad = [{**e, "signatures": [{"keyid": e["signatures"][0]["keyid"], "sig": base64.b64encode(b"A" * 64).decode()}]} for e in bundle["ledger"]]
    assert all(not orch.ledger.verify_entry(e, Keyring({kid: k.public_hex for kid, k in cs})) for e in bad)


def test_ledger_fork_is_detected_and_recorded(tmp_path, repo):
    """VSLA-P-14: a second statement whose ledger does not extend the (root, count) this platform stored is a ledger-fork,
    which is disqualifying and is written into the finder's ledger with a reason."""
    cfg, store, orch = _platform(tmp_path, repo, "platform")
    forch, bundle, cs = _finder_bundle(tmp_path, repo, orch)
    rep = _submit(orch, forch, bundle)
    orch.run_case(rep.id)
    seen = orch.ledger.last_seen(_fid(forch), "finding")
    assert seen == (ledger_root(bundle["ledger"]), 5)
    # the finder presents a different history of the same length (one entry swapped), with a statement that names its root
    forged_ledger = bundle["ledger"][:4] + _seed_ledger(forch, "someone-else", cs, n=1, days=10)
    sub2 = ReportSubmission(**{**demo_submission().model_dump(), "title": "Second finding: path traversal via symlinked storage root", "attestation": {**bundle, "ledger": forged_ledger}})
    rep2 = Report.from_submission(sub2, source=Source.MCP, reporter=Reporter(identity=forch.attestation_identity.name, public_key=forch.attestation_identity.public_hex))
    rep2, _ = orch.intake(rep2, actor=forch.attestation_identity.name)
    orch.run_case(rep2.id)
    ver = store.get_artifact(rep2.id, "vsla_verification")
    assert ver["verified"] <= 1 and ver["pillars"]["identity"]["failed"] == "I4" and "ledger-fork" in next(c["detail"] for c in ver["checks"] if c["id"] == "I4")
    ents = [envelope_payload(e) for e in orch.ledger.entries(_fid(forch))]
    fork = [e for e in ents if e["outcome"] == "ledger-fork"]
    assert fork and "VSLA-P-14" in fork[0]["reason"] and orch.ledger.score(_fid(forch))["score"] == 0.0
    assert "vsla_ledger_fork" in [e.kind for e in store.events(rep2.id)]
    assert orch.ledger.last_seen(_fid(forch), "finding") == seen        # the fork did not move the stored root


def test_reexecution_at_unavailable_revision_is_environment_error(tmp_path, repo):
    """VSLA-P-4: the platform re-executes at subject[1]; a revision its checkout cannot resolve is `environment-error`, E7 fails."""
    other = tmp_path / "other-checkout"
    shutil.copytree(FIXTURE, other)
    git = ["git", "-c", "user.name=x", "-c", "user.email=x@localhost", "-C", str(other)]
    subprocess.run([*git, "init", "-q"], check=True); subprocess.run([*git, "add", "-A"], check=True)
    subprocess.run([*git, "commit", "-q", "-m", "a different history", "--no-gpg-sign"], check=True)
    cfg, store, orch = _platform(tmp_path, repo, "platform")
    forch, bundle, cs = _finder_bundle(tmp_path, repo, orch, repo_path=other)
    rep = _submit(orch, forch, bundle)
    r = orch.run_case(rep.id)
    assert r.status == Status.CLOSED                              # the report is still handled
    rx = envelope_payload(store.get_artifact(rep.id, "vsla_receipt"))["reexecution"]
    assert rx["status"] == "environment-error" and "not available" in rx["reason"] and "observedExit" not in rx
    ver = store.get_artifact(rep.id, "vsla_verification")
    assert ver["verified"] == 1 and ver["pillars"]["evidence"]["failed"] == "E7"


def test_a_sandbox_that_cannot_run_anything_is_environment_error_not_a_false_positive(tmp_path, repo, monkeypatch):
    """VSLA-P-4/P-6: when the platform's own sandbox fails every command (exit 1, as a forbidden `unshare -n` does), the
    receipt is `environment-error`, not `matched` on the exit code alone, and no outcome is written against the finder."""
    cfg, store, orch = _platform(tmp_path, repo, "platform")
    forch, bundle, cs = _finder_bundle(tmp_path, repo, orch)
    from qudisclose.security.sandbox import SandboxResult
    monkeypatch.setattr(LocalSandbox, "run", lambda self, argv, *, timeout=None: SandboxResult(
        returncode=1, stdout="", stderr="unshare: unshare failed: Operation not permitted"))
    rep = _submit(orch, forch, bundle)
    orch.run_case(rep.id)
    rx = envelope_payload(store.get_artifact(rep.id, "vsla_receipt"))["reexecution"]
    assert rx["status"] == "environment-error" and "cannot run a command" in rx["reason"]
    assert orch.ledger.own_entries(_fid(forch)) == []


def test_admission_deferral_issues_not_attempted_receipt_and_slow_lane(tmp_path, repo):
    """VSLA-P-12: over the admission limit the platform defers re-execution, still signs a receipt (not-attempted), routes
    the case to the slow lane and still handles it."""
    cfg, store, orch = _platform(tmp_path, repo, "platform", reexec_per_identity_per_hour=0)
    forch, bundle, cs = _finder_bundle(tmp_path, repo, orch)
    rep = _submit(orch, forch, bundle)
    r = orch.run_case(rep.id)
    assert r.status == Status.CLOSED and r.lane == Lane.SCHEDULED
    receipt = store.get_artifact(rep.id, "vsla_receipt")
    assert verify_receipt(receipt, orch.ledger.keyid, orch.platform_identity)
    rx = envelope_payload(receipt)["reexecution"]
    assert rx["status"] == "not-attempted" and "admission control" in rx["reason"]
    assert {"vsla_reexec_deferred", "slow_lane"} <= {e.kind for e in store.events(rep.id)}
    ver = store.get_artifact(rep.id, "vsla_verification")
    assert ver["verified"] == 1 and ver["pillars"]["evidence"]["failed"] == "E7" and ver["pillars"]["identity"]["level"] == 2
    # unknown identities can be refused outright, without dropping the report
    cfg2, store2, orch2 = _platform(tmp_path, repo, "platform2", reexec_unknown_identities=False)
    forch2, bundle2, _ = _finder_bundle(tmp_path, repo, orch2, with_history=False)
    rep2 = _submit(orch2, forch2, bundle2)
    orch2.run_case(rep2.id)
    assert envelope_payload(store2.get_artifact(rep2.id, "vsla_receipt"))["reexecution"]["status"] == "not-attempted"


def test_submitted_patch_statement_is_reexecuted_reviewed_and_scoped(tmp_path, repo):
    """VSLA-P-4/P-10/F-18, E8: a submitted Patch statement is applied, re-run (reproduction + suite) and reviewed by the
    platform's own reviewer; the finder's review never counts; same-family review or a mixed scope caps the Patch track at L1."""
    # 1. reviewer on the same (scripted) family as the finder's patcher: distinctFamily is false, honestly, so E8 fails
    cfg, store, orch = _platform(tmp_path, repo, "platform")
    forch, bundle, cs = _finder_bundle(tmp_path, repo, orch, track="patch")
    assert envelope_payload(bundle["statement"])["predicate"]["patch"]["review"]["approved"] is True       # the finder says so; irrelevant
    rep = _submit(orch, forch, bundle)
    orch.run_case(rep.id)
    rx = envelope_payload(store.get_artifact(rep.id, "vsla_receipt"))["reexecution"]
    assert rx["status"] == "matched" and rx["applied"] and rx["reproductionPasses"] and rx["suitePasses"] and rx["scope"] == "source-only"
    assert rx["observedExit"] == 1 and rx["securityFailure"] is True and rx["touchedSubject"] is True      # differential: fails before the diff
    assert rx["review"]["approved"] is True and rx["review"]["distinctFamily"] is False and rx["review"]["reviewerFamily"] == "scripted"
    ver = store.get_artifact(rep.id, "vsla_verification")
    assert ver["claimed"] == 2 and ver["verified"] == 1 and ver["pillars"]["evidence"]["failed"] == "E8", ver["pillars"]["evidence"]
    # 2. a reviewer on a distinct family: E8 passes and the Patch track verifies at L2; the ledger gets a patch-track entry
    cfg2, store2, orch2 = _platform(tmp_path, repo, "platform-distinct", reviewer_provider=demo_provider())
    forch2, bundle2, _ = _finder_bundle(tmp_path, repo, orch2, track="patch")
    rep2 = _submit(orch2, forch2, bundle2)
    r2 = orch2.run_case(rep2.id)
    rx2 = envelope_payload(store2.get_artifact(rep2.id, "vsla_receipt"))["reexecution"]
    assert rx2["review"] == {**rx2["review"], "approved": True, "distinctFamily": True, "reviewerFamily": "qwen"}
    ver2 = store2.get_artifact(rep2.id, "vsla_verification")
    assert ver2["claimed"] == 2 and ver2["verified"] == 2, ver2
    outcomes = {envelope_payload(e)["track"]: envelope_payload(e)["outcome"] for e in orch2.ledger.entries(_fid(forch2))[-2:]}
    assert outcomes == {"finding": "accepted", "patch": "accepted"} and r2.vsla["ledger"]["outcomes"] == outcomes
    # 3. a mixed-scope diff (touches pyproject.toml too) caps at L1 regardless of review
    cfg3, store3, orch3 = _platform(tmp_path, repo, "platform-mixed", reviewer_provider=demo_provider())
    forch3, bundle3, _ = _finder_bundle(tmp_path, repo, orch3, track="patch")
    import difflib
    pyproject = (repo / "pyproject.toml").read_text()
    extra = "diff --git a/pyproject.toml b/pyproject.toml\n" + "".join(difflib.unified_diff(
        pyproject.splitlines(True), (pyproject + "# touched by the patch\n").splitlines(True), fromfile="a/pyproject.toml", tofile="b/pyproject.toml"))
    bundle3["patch"]["diff"] = bundle3["patch"]["diff"] + extra
    rep3 = _submit(orch3, forch3, bundle3)
    orch3.run_case(rep3.id)
    rx3 = envelope_payload(store3.get_artifact(rep3.id, "vsla_receipt"))["reexecution"]
    assert rx3["scope"] == "mixed" and rx3["applied"]
    ver3 = store3.get_artifact(rep3.id, "vsla_verification")
    assert ver3["verified"] == 1 and ver3["pillars"]["evidence"]["failed"] == "E8" and "scope=mixed" in next(c["detail"] for c in ver3["checks"] if c["id"] == "E8")


def test_submitted_statement_without_history_verifies_l1(tmp_path, repo):
    """VSLA-P-7: a thin ledger lowers the level to L1 rather than dropping the report (I4 fails)."""
    cfg, store, orch = _platform(tmp_path, repo, "platform")
    forch, bundle, cs = _finder_bundle(tmp_path, repo, orch, with_history=False)
    rep = _submit(orch, forch, bundle)
    r = orch.run_case(rep.id)
    assert r.status == Status.CLOSED
    ver = store.get_artifact(rep.id, "vsla_verification")
    assert ver["claimed"] == 1 and ver["verified"] == 1 and ver["pillars"]["identity"]["failed"] == "I4"


def test_tampered_or_unsigned_statement_is_l0_and_case_still_runs(tmp_path, repo):
    """VSLA-P-2: a statement that fails signature is L0; the report is still handled as an ordinary report; the over-claim is recorded."""
    cfg, store, orch = _platform(tmp_path, repo, "platform")
    forch, bundle, cs = _finder_bundle(tmp_path, repo, orch, with_history=False)
    stmt = envelope_payload(bundle["statement"])
    stmt["predicate"]["claimedLevel"] = 3
    bundle["statement"] = {**bundle["statement"], "payload": base64.b64encode(canonical(stmt)).decode()}
    rep = _submit(orch, forch, bundle)
    assert rep.vsla["submitted"]["verified"] == 0 and rep.vsla["submitted"]["claimed"] == 3
    r = orch.run_case(rep.id)
    assert r.status == Status.CLOSED and store.get_artifact(rep.id, "vsla_verification")["pillars"]["evidence"]["failed"] == "E2"
    ents = [envelope_payload(e) for e in orch.ledger.entries(_fid(forch))]
    assert ents[-1]["claimed"] == 3 and ents[-1]["verified"] == 0          # the over-claim is on the record
    assert orch.ledger.score(_fid(forch), "finding")["over_claims"] == 1


def test_duplicate_submission_is_countersigned_as_duplicate(env):
    cfg, store, audit, provider, orch = env
    rep, _ = orch.intake(new_report(), actor="agent:researcher-1")
    dup = Report.from_submission(demo_submission(), source=Source.MCP, reporter=Reporter(identity="agent:researcher-2"))
    d, is_new = orch.intake(dup, actor="agent:researcher-2")
    assert not is_new and d.id == rep.id
    assert [envelope_payload(e)["outcome"] for e in orch.ledger.entries("agent:researcher-2")] == ["duplicate"]
    assert orch.ledger.score("agent:researcher-2")["n"] == 0            # neutral: buys nothing


def test_malformed_bundle_is_rejected_at_schema_boundary():
    with pytest.raises(ValueError):
        ReportSubmission(**{**demo_submission().model_dump(), "attestation": {"leaves": []}})


def test_platform_refuses_an_ephemeral_key_unless_told_it_is_a_demo(tmp_path, repo):
    cfg = Config(db_dsn=":memory:", out_dir=str(tmp_path / "out"), provider="scripted", repos={"example/vulnpkg": RepoConfig(path=str(repo))})
    store = Store(":memory:")
    with pytest.raises(ConfigError, match="ephemeral"):
        Orchestrator(store=store, audit=AuditLog(store.db, Identity.generate("audit")), config=cfg, provider=demo_provider())
    cfg.vsla.allow_ephemeral_platform_key = True
    Orchestrator(store=store, audit=AuditLog(store.db, Identity.generate("audit")), config=cfg, provider=demo_provider())


# ----------------------------------------------------------------------------- environment pillar

def _l3_statement(tmp_path, *, api_model: bool):
    """A statement with a signed-quote environment bound to its harness, weights and sandbox, from an attestor whose enclave key signs."""
    root, enclave, prov = Identity.generate("root:test-root"), Identity.generate("enclave"), Identity.generate("provider:qwen")
    measurement = "ab" * 48

    class Env:
        def evidence(self, enc, binding):
            return make_signed_quote(root=root, enclave=enc, measurement_hex=measurement, binding=binding)

        def verify(self, env, binding, roots):
            from qudisclose.vsla.environment import verify_signed_quote
            return verify_signed_quote(env, binding, roots)

    finder, platform = Identity.generate("agent:l3"), Identity.generate("platform:cvd.example.org")
    att = Attestor(finder=finder, operator="quome.com", channel={"intake": "https://cvd.example.org/mcp", "intakeKey": f"ed25519:{platform.public_hex}", "declaredIn": "policy"},
                   environment=Env(), enclave=enclave, authorization={"basis": "program", "ref": "https://example/SECURITY.md"})
    wd = "11" * 32
    attn = make_weights_attestation({"model": "qwen3.8:27b", "weights": {"sha256": wd}, "issuedAt": "2026-09-20T14:00:00Z"}, "provider:qwen", prov)
    mbom = [MBOMEntry(role="hunter", provider="qwen", name="qwen3.8:27b", serving="tee", weights_digest=wd, attestation=attn)]
    if api_model:
        mbom.append(MBOMEntry(role="patcher", provider="anthropic", name="claude-opus-5-5", serving="api"))
    from qudisclose.models import ReproductionResult
    from qudisclose.vsla.attest import harness_digest, sandbox_digest
    from qudisclose.vsla.canonical import digest
    repro = ReproductionResult(test_path="tests/test_x.py", test_source="def test_x():\n    assert False\n", fails_on_vulnerable=True,
                               command="python -m pytest -q tests/test_x.py", output_excerpt="")
    t0 = datetime.now(UTC) - timedelta(minutes=5)
    leaves = [{"seq": 0, "kind": "measure", "harness": harness_digest(), "sandbox": sandbox_digest("quome", "vm")},
              {"seq": 1, "kind": "verify", "what": "reproduction", "command": repro.command, "exit": 1, "securityFailure": True, "output": digest("out")}]
    rerun = {"exit": 1, "security_failure": True, "output": "out", "started_at": t0 + timedelta(minutes=1), "finished_at": t0 + timedelta(minutes=2)}
    history = {"ledger": "x", "root": "0" * 64, "entries": 5, "accepted": 5, "rejected": 0, "countersigners": 2, "score": 0.9, "floor": 0.6,
               "oldestAt": (t0 - timedelta(days=100)).isoformat().replace("+00:00", "Z")}
    env = att.finding(sub=demo_submission(), leaves=leaves, mbom=mbom, repro=repro, rerun=rerun, revision="9b2e7c1d4f0a6b3e8c5d2a1f7e9b4c6d8a0f1e2b", sandbox_backend="quome",
                      scanner_flags=[], model_flagged=False, history=history, started=t0, finished=t0 + timedelta(minutes=4), profile="published")
    ring = Keyring({"finder:agent:l3": finder.public_hex, "root:test-root": root.public_hex, "provider:qwen": prov.public_hex, "platform:cvd.example.org": platform.public_hex})
    exp = {"harness": {"qudisclose": {att.harness["version"]: att.harness["digest"]["sha256"]}},
           "measurements": [{"type": "signed-quote", "value": measurement, "harness": att.harness["digest"]["sha256"]}]}
    return env, leaves, Verifier_(ring, exp)


def Verifier_(ring, exp):
    from qudisclose.vsla import Verifier
    return Verifier(ring, expectations=exp)


def test_api_served_model_caps_environment_at_l2_and_attested_tee_reaches_l3(tmp_path):
    """VSLA-F-15/F-17, N3/I5: with every model served from the attested environment and provider-attested, and the quote
    binding enclave key + harness + weights + sandbox, Environment reaches L3 and the enclave key is taken from the quote.
    One api-served model caps Environment at L2 and so I5."""
    env, leaves, v = _l3_statement(tmp_path, api_model=False)
    pred = envelope_payload(env)["predicate"]
    assert pred["claimedLevel"] == 3 and pred["environment"]["enclaveKey"].startswith("ed25519:") and pred["mbom"]["models"][0]["weights"]["attestation"]["payloadType"].endswith("weights-attestation+json")
    res = v.verify(env, leaves=leaves, report=demo_submission())
    assert res.pillars["environment"].level == 3 and res.pillars["identity"].check("I5").ok, res.to_dict()
    assert res.pillars["identity"].failed == "I3" and res.verified == 1                           # no receipt, no ledger: still L1 overall
    env2, leaves2, v2 = _l3_statement(tmp_path, api_model=True)
    assert envelope_payload(env2)["predicate"]["claimedLevel"] == 2                                # the attestor does not even claim L3
    res2 = v2.verify(env2, leaves=leaves2, report=demo_submission())
    assert res2.pillars["environment"].level == 2 and "api-served" in res2.detail("N3")
    assert not res2.pillars["identity"].check("I5").ok                                           # spec: if N3 fails, I5 fails
    # a verifier without the expectation for the measurement fails N3; without the harness expectation it fails N2
    v3 = Verifier_(v.keyring, {**v.expectations, "measurements": []})
    assert v3.verify(env, leaves=leaves).pillars["environment"].failed == "N3"
    assert Verifier_(v.keyring, {}).verify(env, leaves=leaves).pillars["environment"].failed == "N2"


# ----------------------------------------------------------------------------- MCP + CLI surface

def _server(cfg, orch, audit, current):
    reporter = Identity.generate("agent:researcher-1")
    ring = KeyRing(); ring.add(reporter)
    return build_server(config=cfg, orchestrator=orch, audit=audit, server_identity=Identity.generate("server"), issuer_identity=Identity.generate("issuer"),
                       keyring=ring, enable_http_auth=False, identity_resolver=lambda: (current["identity"], set(current["scopes"])))


async def test_get_attestation_and_ledger_tools(env):
    cfg, store, audit, provider, orch = env
    current = {"identity": "agent:researcher-1", "scopes": {"report:read"}}
    mcp = _server(cfg, orch, audit, current)
    rep, _ = orch.intake(new_report(), actor="agent:researcher-1")
    orch.run_case(rep.id)
    async with Client(mcp) as c:
        res = await c.call_tool("get_attestation", {"query": {"report_id": rep.id}})
        out = res.structured_content
        assert out["finding"]["payloadType"] == "application/vnd.in-toto+json" and out["patch"] and out["leaves"] and out["profile"] == "published"
        assert envelope_payload(out["finding"])["predicate"]["profile"] == "published" and envelope_payload(out["finding_embargoed"])["predicate"]["profile"] == "embargoed"
        assert out["vsla"]["finding"]["claimed"] == 1 and out["finder_key"] == orch.attestation_identity.public_hex
        led = (await c.call_tool("get_ledger", {"query": {}})).structured_content
        assert led["finder"] == "agent:researcher-1" and envelope_payload(led["ledgers"]["finding"]["entries"][0])["outcome"] == "accepted"
        assert led["ledgers"]["patch"]["entries"] == [] and led["floor"]["min_age_days"] == 30 and led["finder_key"] == "agent:researcher-1"   # no key pinned for the demo reporter: the ledger id is the name
        pol = json.loads((await c.read_resource("qudisclose://policy")).contents[0].text)
        assert pol["vsla"]["accepts_statements"] and pol["vsla"]["platform_keyid"].startswith("platform:")
        assert pol["vsla"]["reexecution"]["isolation"] == "process" and pol["vsla"]["reexecution"]["production_grade"] is False
        assert pol["vsla"]["floors"]["l2_min_age_days"] == 30 and pol["vsla"]["reexecution"]["admission"]["per_identity_per_hour"] == 20
        assert pol["vsla"]["pinned_countersigners"] == {orch.ledger.keyid: f"ed25519:{orch.platform_identity.public_hex}"}
        att = json.loads((await c.read_resource(f"qudisclose://attestations/{rep.id}")).contents[0].text)
        assert att["finding"]["signatures"][0]["keyid"] == f"finder:{orch.attestation_identity.name}"


async def test_ledger_and_case_metadata_are_scoped_while_embargoed(env):
    """VSLA-P-13: another finder sees neither the ledger of a peer nor the status, lane, timing, timeline or test details of an
    embargoed case; the submitting reporter and an admin do; once public, everyone does."""
    cfg, store, audit, provider, orch = env
    current = {"identity": "agent:researcher-1", "scopes": {"report:read"}}
    mcp = _server(cfg, orch, audit, current)
    rep, _ = orch.intake(new_report(), actor="agent:researcher-1")          # acknowledged, embargoed, not yet run
    async with Client(mcp) as c:
        mine = (await c.call_tool("get_report_status", {"query": {"report_id": rep.id}})).structured_content
        assert mine["status"] == "acknowledged" and "timeline" in mine and "received_at" in mine
        att = (await c.call_tool("get_attestation", {"query": {"report_id": rep.id}})).structured_content
        assert att["profile"] == "embargoed" and att["leaves"] is None
        current["identity"] = "agent:researcher-2"
        other = (await c.call_tool("get_report_status", {"query": {"report_id": rep.id}})).structured_content
        assert other["embargoed"] is True and not {"status", "lane", "severity", "received_at", "timeline", "slo"} & set(other)
        row = (await c.call_tool("list_reports", {"query": {}})).structured_content["reports"][0]
        assert row["title"] == "[embargoed]" and not {"status", "lane", "severity", "received_at"} & set(row)
        res = json.loads((await c.read_resource(f"qudisclose://reports/{rep.id}")).contents[0].text)
        assert res["embargoed"] is True and "submission" not in res and "status" not in res
        with pytest.raises(MCPError, match="report:admin"):
            await c.call_tool("get_ledger", {"query": {"finder": "agent:researcher-1"}})
        own = (await c.call_tool("get_ledger", {"query": {}})).structured_content
        assert own["finder"] == "agent:researcher-2" and own["ledgers"]["finding"]["entries"] == [] and own["ledgers"]["patch"]["entries"] == []
        current["scopes"] = {"report:read", "report:admin"}
        assert (await c.call_tool("get_ledger", {"query": {"finder": "agent:researcher-1"}})).structured_content["finder"] == "agent:researcher-1"
        assert (await c.call_tool("get_report_status", {"query": {"report_id": rep.id}})).structured_content["status"] == "acknowledged"
        current["scopes"] = {"report:read"}
        orch.run_case(rep.id)                                                 # published: public to everyone
        pub = (await c.call_tool("get_report_status", {"query": {"report_id": rep.id}})).structured_content
        assert pub["status"] == "closed" and pub["classification"] == "public" and "timeline" in pub
        assert (await c.call_tool("list_reports", {"query": {}})).structured_content["reports"][0]["status"] == "closed"


def test_cli_verify_attestation(env, tmp_path, capsys):
    from qudisclose.cli import main

    cfg, store, audit, provider, orch = env
    rep, _ = orch.intake(new_report(), actor="agent:researcher-1")
    orch.run_case(rep.id)
    arts = store.artifacts(rep.id)
    n = envelope_payload(arts["vsla_finding"])["predicate"]["transcript"]["leafCount"]
    bundle = tmp_path / "bundle.json"
    bundle.write_text(json.dumps({"statement": arts["vsla_finding"], "leaves": arts["vsla_leaves"][:n]}))
    key = orch.attestation_identity.save(tmp_path / "keys")
    cfgp = tmp_path / "qudisclose.json"
    cfg.keys_dir = str(tmp_path / "keys"); cfg.save(cfgp)
    main(["--config", str(cfgp), "verify-attestation", str(bundle), "--key", str(key)])
    out = json.loads(capsys.readouterr().out)
    assert out["claimed"] == 1 and out["verified"] == 1 and out["track"] == "finding"
    checks = {c["id"]: c for c in out["checks"]}
    assert all(checks[i]["ok"] for i in ("E1", "E2", "E3", "E4", "E5", "E6", "I1", "N1", "N2")) and not checks["E7"]["ok"] and not checks["I4"]["ok"]
    assert checks["E5"]["kind"] == "structural" and checks["E6"]["kind"] == "structural" and checks["E2"]["kind"] == "external"
