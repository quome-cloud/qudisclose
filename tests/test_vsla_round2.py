"""Round-2 review fixes, pinned (spec v1.0, revision 3). Each test is one attack or gap the second review demonstrated
against the platform or its verifier. Requirement ids refer to https://github.com/AAI-Society/vsla/blob/main/spec/v1.0/requirements.md."""

import base64
import os
import sys
from datetime import UTC, datetime, timedelta

import pytest

from qudisclose.demo import demo_submission
from qudisclose.models import Report, Reporter, ReportSubmission, Source, Status
from qudisclose.security import Identity
from qudisclose.security.sandbox import LocalSandbox, run_classified
from qudisclose.vsla import Keyring, Verifier, canonical, make_anchor, make_receipt, verify_anchor
from qudisclose.vsla.attest import diff_paths, non_text_changes, scope_of
from qudisclose.vsla.canonical import parse_canonical
from qudisclose.vsla.dsse import envelope_payload, statement_digest
from qudisclose.vsla.environment import make_signed_quote, quote_body, verify_signed_quote
from qudisclose.vsla.ledger import ledger_root, ledger_well_formed, verified_ledger
from qudisclose.vsla.rubric import countersigner_operator, meets_floor, trust_score
from tests.test_vsla import _classify, _countersigners, _fid, _finder_bundle, _platform, _seed_ledger, _submit

T0 = 20756.583333


def _check(ver, cid):
    return next(c for c in ver["checks"] if c["id"] == cid)


# ----------------------------------------------------------------------------- canonical form (VSLA-F-1)

def test_canonical_ints_beyond_2_53_and_surrogates():
    assert canonical(2**63) == b"9223372036854776000" and canonical(2**53 + 1) == b"9007199254740992" and canonical(10**22) == b"1e+22"
    with pytest.raises(ValueError):
        canonical({"s": "\ud800"})
    for bad in (b'{"a":1,"a":2}', b'{"b":1,"a":2}', b'{"a": 1}'):
        with pytest.raises(ValueError):
            parse_canonical(bad)


def test_non_canonical_payload_fails_e1(tmp_path, repo):
    """A payload with two `claimedLevel` keys parses differently in different parsers; it is rejected at E1, never signed into a level."""
    cfg, store, orch = _platform(tmp_path, repo, "platform")
    forch, bundle, cs = _finder_bundle(tmp_path, repo, orch)
    raw = base64.b64decode(bundle["statement"]["payload"]).decode()
    i = raw.rfind('"vslaVersion":"1.0"')
    forged = (raw[:i] + '"vslaVersion":"1.0","claimedLevel":3' + raw[i + len('"vslaVersion":"1.0"'):]).encode()
    from qudisclose.vsla.dsse import pae, PAYLOAD_TYPE
    env = {**bundle["statement"], "payload": base64.b64encode(forged).decode(),
           "signatures": [{"keyid": f"finder:{forch.attestation_identity.name}", "sig": base64.b64encode(forch.attestation_identity.sign(pae(PAYLOAD_TYPE, forged))).decode()}]}
    res = orch.verifier.verify(env)
    assert res.verified == 0 and res.pillars["evidence"].failed == "E1" and "canonical" in res.detail("E1")


# ----------------------------------------------------------------------------- the receipt (VSLA-P-3, V-1)

def test_self_signed_receipt_is_not_a_receipt(tmp_path, repo):
    """A receipt signed by the finder's own pinned key, or by any pinned non-platform key, fails I3 and is not read by E7,
    even for a verifier with no `platform_keyid` configured (round 2, probe P1)."""
    cfg, store, orch = _platform(tmp_path, repo, "platform")
    forch, bundle, cs = _finder_bundle(tmp_path, repo, orch)
    orch.keyring.add(f"finder:{forch.attestation_identity.name}", forch.attestation_identity)
    stmt = bundle["statement"]
    rev = envelope_payload(stmt)["subject"][1]["digest"]["gitCommit"]
    rx = {"status": "matched", "revision": rev, "observedExit": 1, "securityFailure": True, "touchedSubject": True, "outputDigest": {"sha256": "0" * 64},
          "sandbox": {"backend": "quome", "isolation": "vm"}}
    v = Verifier(orch.keyring, platform_keyid=None, expectations=orch.expectations)
    fake = make_receipt(stmt, platform=forch.attestation_identity, keyid=f"finder:{forch.attestation_identity.name}", channel=cfg.public_url,
                        received_at=datetime.now(UTC).isoformat(), reexecution=rx)
    res = v.verify(stmt, receipt=fake, ledger_entries=bundle["ledger"], expected_intake=cfg.public_url)
    assert res.verified == 1 and not res.ok("I3") and not res.ok("E7") and "ignored" in res.detail("E7")
    kid, mkey = cs[0]
    fake = make_receipt(stmt, platform=mkey, keyid=kid, channel=cfg.public_url, received_at=datetime.now(UTC).isoformat(), reexecution=rx)
    res = v.verify(stmt, receipt=fake, ledger_entries=bundle["ledger"], expected_intake=cfg.public_url)
    assert not res.ok("I3") and not res.ok("E7")
    # the genuine platform receipt, by the key channel.intakeKey names, counts
    real = make_receipt(stmt, platform=orch.platform_identity, keyid=orch.ledger.keyid, channel=cfg.public_url, received_at=datetime.now(UTC).isoformat(), reexecution=rx)
    res = v.verify(stmt, receipt=real, ledger_entries=bundle["ledger"], expected_intake=cfg.public_url)
    assert res.ok("I3") and res.ok("E7") and res.verified == 2
    # ... unless it is dated before the run or far in the future
    for at in ("2001-01-01T00:00:00Z", (datetime.now(UTC) + timedelta(days=1)).isoformat()):
        bad = make_receipt(stmt, platform=orch.platform_identity, keyid=orch.ledger.keyid, channel=cfg.public_url, received_at=at, reexecution=rx)
        assert not v.verify(stmt, receipt=bad, expected_intake=cfg.public_url).ok("I3")


def test_anchor_roundtrip_and_require_anchor(tmp_path, repo):
    """VSLA-P-16: a signed-anchor under a pinned log key verifies and commits to its receipt; a verifier can require one."""
    cfg, store, orch = _platform(tmp_path, repo, "platform")
    forch, bundle, cs = _finder_bundle(tmp_path, repo, orch)
    orch.keyring.add(f"finder:{forch.attestation_identity.name}", forch.attestation_identity)
    log = Identity.generate("log:test-log")
    orch.keyring.add("log:test-log", log)
    stmt = bundle["statement"]
    rev = envelope_payload(stmt)["subject"][1]["digest"]["gitCommit"]
    rx = {"status": "matched", "revision": rev, "observedExit": 1, "securityFailure": True, "touchedSubject": True, "sandbox": {"backend": "quome", "isolation": "vm"}}
    now = datetime.now(UTC)
    anchored = make_receipt(stmt, platform=orch.platform_identity, keyid=orch.ledger.keyid, channel=cfg.public_url, received_at=now.isoformat(), reexecution=rx,
                            anchor_log=("test-log", log, "e1", (now + timedelta(seconds=30)).isoformat()))
    plain = make_receipt(stmt, platform=orch.platform_identity, keyid=orch.ledger.keyid, channel=cfg.public_url, received_at=now.isoformat(), reexecution=rx)
    ok, form, why = verify_anchor(envelope_payload(anchored), orch.keyring)
    assert ok and form == "signed-timestamp" and why == "signed-timestamp in test-log"
    # a signed-timestamp satisfies require_anchor only when the policy accepts that form (round 3: it is not log inclusion)
    v = Verifier(orch.keyring, platform_keyid=orch.ledger.keyid, expectations=orch.expectations, require_anchor=True, accept_timestamp_anchor=True)
    assert v.verify(stmt, receipt=anchored, ledger_entries=bundle["ledger"], expected_intake=cfg.public_url).verified == 2
    strict = Verifier(orch.keyring, platform_keyid=orch.ledger.keyid, expectations=orch.expectations, require_anchor=True)
    res = strict.verify(stmt, receipt=anchored, ledger_entries=bundle["ledger"], expected_intake=cfg.public_url)
    assert res.verified == 1 and not res.ok("I3") and not res.ok("E7") and "signed-timestamp" in res.detail("I3")
    res = v.verify(stmt, receipt=plain, ledger_entries=bundle["ledger"], expected_intake=cfg.public_url)
    assert res.verified == 1 and not res.ok("I3") and not res.ok("E7") and "no anchor" in res.detail("I3")
    assert orch.verifier.verify(stmt, receipt=plain, ledger_entries=bundle["ledger"], expected_intake=cfg.public_url).verified == 2   # not required by default
    # an anchor the log signed over a different receipt does not transfer
    body = envelope_payload(plain)
    foreign = make_anchor({**body, "receivedAt": (now - timedelta(seconds=5)).isoformat()}, log="test-log", key=log, entry_id="e2", integrated_time=(now + timedelta(seconds=30)).isoformat())
    assert verify_anchor({**body, "anchor": foreign}, orch.keyring)[2] == "timestamp commits to a different receipt"


def test_require_isolation_gates_e7(tmp_path, repo):
    """VSLA-P-11: a verifier that requires vm isolation does not accept this platform's process re-execution."""
    cfg, store, orch = _platform(tmp_path, repo, "platform", require_isolation="vm")
    forch, bundle, cs = _finder_bundle(tmp_path, repo, orch)
    rep = _submit(orch, forch, bundle)
    orch.run_case(rep.id)
    ver = store.get_artifact(rep.id, "vsla_verification")
    rx = envelope_payload(store.get_artifact(rep.id, "vsla_receipt"))["reexecution"]
    assert rx["status"] == "matched" and rx["sandbox"]["isolation"] == "process"
    assert ver["verified"] == 1 and ver["pillars"]["evidence"]["failed"] == "E7" and "isolation=process" in _check(ver, "E7")["detail"]


# ----------------------------------------------------------------------------- the ledger (VSLA-V-5, P-14)

def test_borrowed_ledger_counts_for_nothing(tmp_path, repo):
    """Another finder's countersigned ledger is dropped under a different key (round 2, probe P3)."""
    cfg, store, orch = _platform(tmp_path, repo, "platform")
    forch_a, bundle_a, cs = _finder_bundle(tmp_path, repo, orch)
    forch_b, bundle_b, _ = _finder_bundle(tmp_path, repo, orch, countersigners=cs)
    orch.keyring.add(f"finder:{forch_a.attestation_identity.name}", forch_a.attestation_identity)
    res = orch.verifier.verify(bundle_a["statement"], ledger_entries=bundle_b["ledger"], expected_intake=cfg.public_url)
    assert not res.ok("I4") and "5 outcome entries dropped" in res.detail("I4")
    kept, dropped = verified_ledger(bundle_b["ledger"], orch.keyring, finder=f"ed25519:{forch_a.attestation_identity.public_hex}")
    assert kept == [] and dropped == 5
    kept, dropped = verified_ledger(bundle_b["ledger"], orch.keyring, finder=f"ed25519:{forch_b.attestation_identity.public_hex}")
    assert len(kept) == 5 and dropped == 0


def test_finding_ledger_buys_no_patch_trust(tmp_path, repo):
    """A Patch statement presented with a Finding-track ledger fails I4 (round 2, probe P4); the same finder's Patch ledger passes."""
    cfg, store, orch = _platform(tmp_path, repo, "platform")
    forch, bundle, cs = _finder_bundle(tmp_path, repo, orch, track="patch")
    orch.keyring.add(f"finder:{forch.attestation_identity.name}", forch.attestation_identity)
    assert {envelope_payload(e)["track"] for e in bundle["ledger"]} == {"patch"}
    scratch_cfg, scratch_store, scratch = _platform(tmp_path, repo, "scratch", countersigners=cs)
    finding_ledger = _seed_ledger(scratch, _fid(forch), cs, finder_key=forch.attestation_identity.public_hex, track="finding")
    res = orch.verifier.verify(bundle["statement"], ledger_entries=finding_ledger, expected_intake=cfg.public_url)
    assert not res.ok("I4") and "5 outcome entries dropped" in res.detail("I4")
    res = orch.verifier.verify(bundle["statement"], ledger_entries=bundle["ledger"], expected_intake=cfg.public_url)
    assert res.ok("I4")


def test_presented_order_cannot_move_the_score(tmp_path, repo):
    """Round 3: the finder owns the index. Any order is well formed; the rubric window is by countersigned `at`, so reordering
    changes nothing; reordering does break the root the statement commits to (history.root), which is the finder's own problem."""
    cfg, store, orch = _platform(tmp_path, repo, "platform")
    forch, bundle, cs = _finder_bundle(tmp_path, repo, orch)
    orch.keyring.add(f"finder:{forch.attestation_identity.name}", forch.attestation_identity)
    assert ledger_well_formed(bundle["ledger"])[0] and ledger_well_formed(bundle["ledger"][::-1])[0]
    res = orch.verifier.verify(bundle["statement"], ledger_entries=bundle["ledger"][::-1], expected_intake=cfg.public_url)
    assert not res.ok("I4") and "history.root mismatch" in res.detail("I4")
    first = [{"outcome": "rejected", "countersigner": "platform:a", "at": T0 - 5, "claimed": 1, "verified": 1} for _ in range(10)] + \
            [{"outcome": "accepted", "countersigner": ["platform:a", "platform:b"][i % 2], "at": T0 - 100 + i, "claimed": 1, "verified": 1} for i in range(50)]
    assert trust_score(first, now_days=T0)["score"] == trust_score(first[10:] + first[:10], now_days=T0)["score"]


def test_countersigners_counted_per_operator():
    """trust-rubric.md: platform:acme and maintainer:acme are one countersigner (round 2, probe P11)."""
    assert countersigner_operator("platform:acme.example") == countersigner_operator("maintainer:acme.example") == "acme.example"
    ents = [{"outcome": "accepted", "countersigner": ["platform:acme.example", "maintainer:acme.example"][i % 2], "at": T0 - 40, "claimed": 1, "verified": 1} for i in range(6)]
    ts = trust_score(ents, now_days=T0)
    assert ts["countersigners"] == 1 and not meets_floor(ts)[0]


def test_platforms_own_entry_must_appear_in_the_next_ledger(tmp_path, repo):
    """VSLA-P-14: a finder that resubmits the ledger it presented before, without the entry this platform wrote at close,
    is recorded as a ledger-fork (round 2, probe Q5). Round 3: the stored root is what the platform was SHOWN; its own entry
    carries no index and must be included anywhere."""
    cfg, store, orch = _platform(tmp_path, repo, "platform")
    forch, bundle, cs = _finder_bundle(tmp_path, repo, orch)
    rep = _submit(orch, forch, bundle)
    orch.run_case(rep.id)
    fid = _fid(forch)
    own = orch.ledger.own_entries(fid, "finding")
    assert [envelope_payload(e)["outcome"] for e in own] == ["accepted"] and "seq" not in envelope_payload(own[0])
    assert orch.ledger.last_seen(fid, "finding") == (ledger_root(bundle["ledger"]), 5)
    sub2 = ReportSubmission(**{**demo_submission().model_dump(), "title": "Second finding with the stale ledger that omits the platform's entry", "attestation": bundle})
    rep2 = Report.from_submission(sub2, source=Source.MCP, reporter=Reporter(identity=forch.attestation_identity.name, public_key=forch.attestation_identity.public_hex))
    rep2, _ = orch.intake(rep2, actor=forch.attestation_identity.name)
    orch.run_case(rep2.id)
    ver = store.get_artifact(rep2.id, "vsla_verification")
    assert not _check(ver, "I4")["ok"] and "omits 1 entry" in _check(ver, "I4")["detail"]
    ents = [envelope_payload(e) for e in orch.ledger.entries(fid)]
    forks = [e for e in ents if e["outcome"] == "ledger-fork"]
    assert len(forks) == 1 and "omits" in forks[0]["reason"] and "seq" not in forks[0] and orch.ledger.score(fid, "finding")["score"] == 0.0
    own_now = orch.ledger.own_entries(fid, "finding")
    assert [envelope_payload(e)["outcome"] for e in own_now] == ["accepted", "ledger-fork", "accepted"]      # the second case still closed
    assert [envelope_payload(e)["outcome"] for e in orch.ledger.missing_from(fid, "finding", bundle["ledger"] + own)] == ["ledger-fork", "accepted"]
    assert orch.ledger.last_seen(fid, "finding") == (ledger_root(bundle["ledger"]), 5)       # the fork did not move the shown root
    # a finder that includes what it was given, in any position, extends the shown root and omits nothing
    extended = bundle["ledger"][:2] + own_now + bundle["ledger"][2:]
    assert ledger_well_formed(extended)[0] and orch.ledger.missing_from(fid, "finding", extended) == []
    assert ledger_root(extended[:5]) != orch.ledger.last_seen(fid, "finding")[0]   # ...but it must extend the SHOWN prefix: own entries go after it
    assert ledger_root((bundle["ledger"] + own_now)[:5]) == orch.ledger.last_seen(fid, "finding")[0]


# ----------------------------------------------------------------------------- outcomes (VSLA-P-6, P-15)

def test_false_positive_is_never_written_over_a_matched_receipt(tmp_path, repo):
    """The ledger outcome follows the platform's re-execution of the FINDER's test, never the platform's own reproducer
    agent: a matched receipt plus a failed platform reproduction is reproduced-unresolved (round 2, probe Q6)."""
    cfg, store, orch = _platform(tmp_path, repo, "platform")
    passing = "def test_nothing():\n    assert True\n"
    orch.provider.inner.scripts["reproducer"] = lambda u, t: (t["write_file"]("tests/test_fp.py", passing), dict(
        test_path="tests/test_fp.py", test_source=passing, fails_on_vulnerable=True, command="python -m pytest -q tests/test_fp.py", output_excerpt=""))[-1]
    forch, bundle, cs = _finder_bundle(tmp_path, repo, orch)
    rep = _submit(orch, forch, bundle)
    r = orch.run_case(rep.id)
    rx = envelope_payload(store.get_artifact(rep.id, "vsla_receipt"))["reexecution"]
    assert r.status == Status.FAILED and rx["status"] == "matched" and rx["securityFailure"] is True
    ents = [envelope_payload(e) for e in orch.ledger.own_entries(_fid(forch))]
    assert [e["outcome"] for e in ents] == ["reproduced-unresolved"]
    assert orch.ledger.score(_fid(forch), "finding")["n"] == 0                      # neutral: nothing held against the finder
    # a submitted test that does NOT fail by assertion at the subject revision is a false-positive, with the classifier's reason
    cfg2, store2, orch2 = _platform(tmp_path, repo, "platform2")
    forch2, bundle2, _ = _finder_bundle(tmp_path, repo, orch2)
    bundle2["reproduction"] = {**bundle2["reproduction"], "test_source": passing}
    rep2 = _submit(orch2, forch2, bundle2)
    orch2.run_case(rep2.id)
    rx2 = envelope_payload(store2.get_artifact(rep2.id, "vsla_receipt"))["reexecution"]
    assert rx2["status"] == "mismatched" and rx2["securityFailure"] is False
    # the platform's own pipeline still reproduced (its reproducer wrote a real test) so the case ran; the finder's claim is what the ledger judges
    outcomes = {envelope_payload(e)["track"]: envelope_payload(e) for e in orch2.ledger.own_entries(_fid(forch2))}
    assert "finding" in outcomes


def test_rejected_by_triage_carries_the_rationale(env):
    """VSLA-P-6: a negative outcome a model decided carries the model's rationale and its digest, not boilerplate."""
    from tests.conftest import new_report
    from tests.test_vsla import _triage_ok
    cfg, store, audit, provider, orch = env
    provider.scripts["triage"] = lambda user, tools: {**_triage_ok(), "is_vulnerability": False, "lane": "reject", "rationale": "The reported path is normalised by resolve_path before use; no traversal is possible."}
    from tests.conftest import new_report
    rep, _ = orch.intake(new_report(), actor="agent:researcher-1")
    orch.run_case(rep.id)
    reason = envelope_payload(orch.ledger.entries(orch.finder_id("agent:researcher-1", rep.reporter.public_key))[0])["reason"]
    assert reason.startswith("triage (") and "normalised by resolve_path" in reason


# ----------------------------------------------------------------------------- the platform (VSLA-P-4, P-11, P-12)

def test_admission_defers_unknown_identities_by_default(tmp_path, repo):
    """VSLA-P-12: an identity that presents no ledger entry verifiable under a pinned countersigner is deferred (not-attempted
    receipt, slow lane) unless the operator opts in."""
    cfg, store, orch = _platform(tmp_path, repo, "platform")
    assert cfg.vsla.reexec_unknown_identities is False
    forch, bundle, _ = _finder_bundle(tmp_path, repo, orch, with_history=False)
    rep = _submit(orch, forch, bundle)
    orch.run_case(rep.id)
    rx = envelope_payload(store.get_artifact(rep.id, "vsla_receipt"))["reexecution"]
    assert rx["status"] == "not-attempted" and "pinned countersigner" in rx["reason"]
    cfg2, store2, orch2 = _platform(tmp_path, repo, "platform2", reexec_unknown_identities=True)
    forch2, bundle2, _ = _finder_bundle(tmp_path, repo, orch2, with_history=False)
    rep2 = _submit(orch2, forch2, bundle2)
    orch2.run_case(rep2.id)
    assert envelope_payload(store2.get_artifact(rep2.id, "vsla_receipt"))["reexecution"]["status"] == "matched"
    # a presented ledger countersigned by keys this platform does NOT pin is still "unknown"
    cfg3, store3, orch3 = _platform(tmp_path, repo, "platform3")
    forch3, bundle3, cs3 = _finder_bundle(tmp_path, repo, orch3)
    for kid, _ in cs3:
        orch3.keyring._keys.pop(kid)
    rep3 = _submit(orch3, forch3, bundle3)
    orch3.run_case(rep3.id)
    assert envelope_payload(store3.get_artifact(rep3.id, "vsla_receipt"))["reexecution"]["status"] == "not-attempted"


def test_receipt_is_issued_once(tmp_path, repo):
    """A resumed case does not re-execute or overwrite the receipt it already signed."""
    cfg, store, orch = _platform(tmp_path, repo, "platform")
    forch, bundle, cs = _finder_bundle(tmp_path, repo, orch)
    rep = _submit(orch, forch, bundle)
    orch.run_case(rep.id)
    receipt = store.get_artifact(rep.id, "vsla_receipt")
    r = store.get_report(rep.id); r.status = Status.ACKNOWLEDGED; store.save_report(r)
    orch.run_case(rep.id)
    assert store.get_artifact(rep.id, "vsla_receipt") == receipt and "vsla_receipt_exists" in [e.kind for e in store.events(rep.id)]


def test_pinned_finder_key_with_a_window_is_not_overwritten(tmp_path, repo):
    """VSLA-F-20: a submission never replaces a pinned key's validity window."""
    cfg, store, orch = _platform(tmp_path, repo, "platform")
    forch, bundle, cs = _finder_bundle(tmp_path, repo, orch)
    kid = f"finder:{forch.attestation_identity.name}"
    orch.keyring.add(kid, {"public": forch.attestation_identity.public_hex, "revokedAt": "2020-01-01T00:00:00Z"})
    rep = _submit(orch, forch, bundle)
    assert orch.keyring.to_dict()[kid]["revokedAt"] == "2020-01-01T00:00:00Z"
    assert rep.vsla["submitted"]["verified"] == 0 and rep.vsla["submitted"]["pillars"]["identity"]["failed"] == "I1"


def test_touched_subject_is_the_platforms_package_and_says_what_it_means(repo):
    """VSLA-P-4: `touchedSubject` means the run imported (importtime) or covered (coverage) a module of the package the
    platform names; it is cleared by `import vulnpkg` and nothing more, and the receipt says so."""
    r, c = _classify(repo, "import vulnpkg\n\ndef test_x():\n    assert False\n", subject="vulnpkg")
    assert c.security_failure and c.touched_subject is True and c.touched_means in ("imported", "covered")
    r, c = _classify(repo, "def test_x():\n    assert False\n", subject="vulnpkg")
    assert c.security_failure and c.touched_subject is False
    assert c.to_dict()["touched_means"] == c.touched_means


def test_forged_runner_report_is_not_a_security_failure(repo):
    """VSLA-F-5: a test that writes a fake junit report and hard-exits is caught when the report path is guessed (no report)
    or when the report disagrees with pytest's summary line and exit code (inconsistent). A test that forges all three
    together is the documented residual."""
    guessed = '''
import os
def test_x():
    open(".qudisclose-junit.xml", "w").write('<testsuites><testsuite tests="1" failures="1" errors="0"><testcase classname="t" name="test_real">'
        '<failure message="AssertionError: path escaped">E       assert False</failure></testcase></testsuite></testsuites>')
    os._exit(1)
'''
    r, c = _classify(repo, guessed)
    assert r.returncode == 1 and not c.security_failure and "no junit report" in c.reason
    via_argv = '''
import os, sys
def test_x():
    path = next(a.split("=", 1)[1] for a in sys.argv if a.startswith("--junitxml="))
    open(path, "w").write('<testsuites><testsuite tests="1" failures="1" errors="0"><testcase classname="t" name="test_real">'
        '<failure message="AssertionError: path escaped">E       assert False</failure></testcase></testsuite></testsuites>')
    os._exit(1)
'''
    r, c = _classify(repo, via_argv)
    assert r.returncode == 1 and not c.security_failure and c.consistent is False and "inconsistent" in c.reason
    # an honest assertion failure is consistent on all three accounts
    r, c = _classify(repo, "from vulnpkg import resolve_path\n\ndef test_x(tmp_path):\n    assert '..' not in str(resolve_path(tmp_path, '../x'))\n")
    assert c.security_failure and c.consistent is True


@pytest.mark.skipif(sys.platform != "darwin" or not os.path.exists("/usr/bin/sandbox-exec"), reason="macOS sandbox-exec netfilter only")
def test_process_sandbox_denies_network_on_macos(repo):
    """VSLA-P-11: without a network namespace, the macOS process sandbox still cuts egress with sandbox-exec, and says so."""
    sb = LocalSandbox(repo, case_id="net")
    assert sb.netfilter() == "sandbox-exec" and sb.isolation_detail()["netns"] == "sandbox-exec"
    sb.create()
    try:
        r = sb.run(["python", "-c", "import socket; socket.setdefaulttimeout(3); socket.getaddrinfo('example.com', 443); print('DNS ok')"])
        assert r.returncode != 0 and "DNS ok" not in r.stdout
        r = sb.run(["python", "-c", "import socket; socket.create_connection(('1.1.1.1', 53), timeout=3)"])
        assert r.returncode != 0
    finally:
        sb.destroy()


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux netfilter only")
def test_unshare_that_cannot_create_a_namespace_is_not_claimed(repo, tmp_path, monkeypatch):
    """VSLA-P-11: where `unshare` exists but the host forbids unprivileged namespaces (Ubuntu 24.04's default
    kernel.apparmor_restrict_unprivileged_userns=1), the sandbox must neither claim a namespace nor wrap every command in one
    that fails."""
    shim = tmp_path / "bin"
    shim.mkdir()
    (shim / "unshare").write_text("#!/bin/sh\necho 'unshare: unshare failed: Operation not permitted' >&2\nexit 1\n")
    (shim / "unshare").chmod(0o755)
    monkeypatch.setenv("PATH", f"{shim}{os.pathsep}{os.environ['PATH']}")
    sb = LocalSandbox(repo, case_id="netns")
    assert sb.netfilter() == "none" and sb.isolation_detail()["netns"] == "none"
    sb.create()
    try:
        assert sb.run(["python", "-c", "pass"]).returncode == 0
    finally:
        sb.destroy()


# ----------------------------------------------------------------------------- scope (VSLA-F-18)

def test_scope_sees_renames_modes_binaries_and_submodules():
    rename = "diff --git a/tests/fixtures/payload.bin b/vulnpkg/payload.py\nsimilarity index 100%\nrename from tests/fixtures/payload.bin\nrename to vulnpkg/payload.py\n"
    mode = "diff --git a/scripts/release/publish.sh b/scripts/release/publish.sh\nold mode 100644\nnew mode 100755\n"
    binary = "diff --git a/vulnpkg/data.so b/vulnpkg/data.so\nindex 0000000..1111111 100644\nGIT binary patch\nliteral 4\nLc${NkU|<9?\n\n"
    submod = "diff --git a/.gitmodules b/.gitmodules\n--- a/.gitmodules\n+++ b/.gitmodules\n@@ -0,0 +1,3 @@\n+[submodule \"x\"]\n+ path = vendor/x\n+ url = https://evil.example/x\n"
    plain = "diff --git a/vulnpkg/files.py b/vulnpkg/files.py\n--- a/vulnpkg/files.py\n+++ b/vulnpkg/files.py\n@@ -1 +1 @@\n-vulnerable\n+fixed\n"
    assert diff_paths(rename) == ["tests/fixtures/payload.bin", "vulnpkg/payload.py"] and scope_of(diff_paths(rename), rename) == "mixed"
    assert diff_paths(mode) == ["scripts/release/publish.sh"] and scope_of(diff_paths(mode), mode) == "mixed" and non_text_changes(mode)
    assert diff_paths(binary) == ["vulnpkg/data.so"] and scope_of(diff_paths(binary), binary) == "mixed"
    assert scope_of(diff_paths(submod), submod) == "mixed" and scope_of(["conftest.py"]) == "mixed" and scope_of(["setup.cfg"]) == "mixed"
    assert diff_paths(plain) == ["vulnpkg/files.py"] and scope_of(diff_paths(plain), plain) == "source-only"
    # a mode change on an otherwise source-only path is still mixed
    assert scope_of(["vulnpkg/files.py"], "diff --git a/vulnpkg/files.py b/vulnpkg/files.py\nold mode 100644\nnew mode 100755\n") == "mixed"


# ----------------------------------------------------------------------------- environment (VSLA-F-15)

def test_two_operator_needs_two_distinct_cosigners():
    """A two-operator quote whose co-signers are one root twice is one operator, not "neither operator alone" (round 2, probe P5)."""
    root, other, enclave = Identity.generate("root:solo"), Identity.generate("root:second"), Identity.generate("enclave")
    ring = Keyring({"root:solo": root.public_hex, "root:second": other.public_hex})
    binding = {"enclaveKey": enclave.public_hex, "harness": "a" * 64, "weights": ["b" * 64], "sandbox": "c" * 64}

    def env_for(cos, keys):
        env = {"type": "two-operator", "measurement": {"algorithm": "sha384", "value": "d" * 96}, "measures": ["weights", "harness", "policy", "sandbox", "signingKey"],
               "rootOfTrust": cos[0], "enclaveKey": f"ed25519:{enclave.public_hex}", "coSigners": cos}
        env["quote"] = ";".join(base64.b64encode(k.sign(quote_body(env, binding))).decode() for k in keys)
        return env

    assert not verify_signed_quote(env_for(["solo", "solo"], [root, root]), binding, ring)
    assert not verify_signed_quote(env_for(["solo"], [root]), binding, ring)
    assert verify_signed_quote(env_for(["solo", "second"], [root, other]), binding, ring)
    assert verify_signed_quote(make_signed_quote(root=root, enclave=enclave, measurement_hex="d" * 96, binding=binding, root_name="solo"), binding, ring)
