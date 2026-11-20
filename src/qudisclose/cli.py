"""qudisclose command line."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from typing import Any
from pathlib import Path

from qudisclose.config import Config, RepoConfig
from qudisclose.models import ReportSubmission
from qudisclose.db import ensure_database
from qudisclose.security import AuditLog, CredentialBroker, Identity, TokenIssuer
from qudisclose.security.keys import KeyRing
from qudisclose.store import Store


def _keys(cfg: Config) -> tuple[Identity, Identity, Identity]:
    d = Path(cfg.keys_dir)
    names = ("server", "issuer", "audit")
    out = []
    for n in names:
        p = d / f"{n}.json"
        out.append(Identity.load(p) if p.exists() else Identity.generate(n))
        if not p.exists():
            out[-1].save(d)
    return out[0], out[1], out[2]


def _attest_key(cfg: Config) -> Identity:
    """The deployment's VSLA finder key (signs the statements qudisclose emits for its own cases)."""
    p = Path(cfg.keys_dir) / "attestation.json"
    if p.exists():
        return Identity.load(p)
    host = cfg.public_url.split("//", 1)[-1].split("/", 1)[0]
    ident = Identity.generate(cfg.vsla.finder_identity or f"qudisclose@{host}")
    Path(cfg.keys_dir).mkdir(parents=True, exist_ok=True)
    (Path(cfg.keys_dir) / "attestation.json").write_text(json.dumps({"name": ident.name, "public": ident.public_hex,
        "private": ident.private_key.private_bytes_raw().hex()}, indent=2))  # type: ignore[union-attr]
    (Path(cfg.keys_dir) / "attestation.json").chmod(0o600)
    return ident


def _keyring(cfg: Config) -> KeyRing:
    ring = KeyRing()
    for name, hexkey in cfg.trusted_reporters.items():
        ring.add(Identity.from_public_hex(name, hexkey))
    return ring


def _store(cfg: Config) -> Store:
    """Open the store, creating the Postgres database first if it does not exist (no-op for SQLite)."""
    ensure_database(cfg.db_dsn)
    return Store(cfg.db_dsn)


def _provider_for(cfg: Config, provider: str, model: str | None = None):
    """Build an agent provider for an explicit provider/model (used by the CLI default and the dashboard's
    per-run picker). `local`/`openai` is the self-hosted OpenAI-compatible endpoint; `anthropic` is Claude
    (source leaves the host — the dashboard surfaces this explicitly); `scripted` is the offline demo."""
    if provider == "scripted":
        from qudisclose.demo import demo_provider
        return demo_provider()
    if provider in ("local", "openai"):
        from qudisclose.agents.provider import OpenAICompatProvider
        inf = cfg.inference
        return OpenAICompatProvider(base_url=inf.base_url, model=model or inf.model,
                                    api_key=os.environ.get(inf.api_key_env, "ollama"))
    if provider == "claude":  # local Claude Code CLI (`claude -p`) — uses your Claude Code login, no API key
        from qudisclose.agents.provider import ClaudeCliProvider
        return ClaudeCliProvider(model=model)
    from qudisclose.agents import AnthropicProvider
    return AnthropicProvider(model=model or cfg.model)


def _provider(cfg: Config):
    return _provider_for(cfg, cfg.provider)


def _reviewer_provider(cfg: Config):
    """VSLA-P-10: a reviewer on a different provider/model family than the patcher, when `inference.reviewer_provider`
    (or `reviewer_model`) is set. None means the reviewer runs on the pipeline provider and `distinctFamily` is false."""
    inf = cfg.inference
    if not inf.reviewer_provider and not inf.reviewer_model:
        return None
    prov = inf.reviewer_provider or cfg.provider
    if prov in ("local", "openai"):
        from qudisclose.agents.provider import OpenAICompatProvider
        return OpenAICompatProvider(base_url=inf.reviewer_base_url or inf.base_url, model=inf.reviewer_model or inf.model,
                                    api_key=os.environ.get(inf.api_key_env, "ollama"))
    return _provider_for(cfg, prov, inf.reviewer_model)


def _orchestrator(cfg: Config, store: Store, audit: AuditLog, provider=None):
    from qudisclose.orchestrator import Orchestrator
    from qudisclose.publisher import GitHubPublisher, LocalPublisher

    broker = CredentialBroker(require_human_for=frozenset(
        {p for p, flag in (("pr:create", cfg.policy.require_human_for_merge), ("advisory:publish", cfg.policy.require_human_for_publish)) if flag}))
    publisher = GitHubPublisher(broker) if os.environ.get(cfg.github_token_env) else LocalPublisher(cfg.out_dir)
    server, _, _ = _keys(cfg)
    return Orchestrator(store=store, audit=audit, config=cfg, provider=provider or _provider(cfg), broker=broker, publisher=publisher,
                        platform_identity=server, attestation_identity=_attest_key(cfg), reviewer_provider=_reviewer_provider(cfg))


def cmd_init(a: argparse.Namespace) -> None:
    cfg = Config()
    if a.repo and a.path:
        cfg.repos[a.repo] = RepoConfig(path=str(Path(a.path).resolve()), test_command=a.test_command)
    cfg.provider = a.provider
    cfg.save(a.config)
    server, issuer, audit = _keys(cfg)
    print(f"wrote {a.config}; keys in {cfg.keys_dir}/ (server pubkey {server.public_hex[:16]}…)")


def cmd_register_reporter(a: argparse.Namespace) -> None:
    cfg = Config.load(a.config)
    if a.generate:
        ident = Identity.generate(a.name)
        ident.save(Path(a.generate))
        pub = ident.public_hex
        print(f"generated reporter key -> {Path(a.generate) / (a.name + '.json')}")
    else:
        pub = a.public_key
    cfg.trusted_reporters[a.name] = pub
    cfg.save(a.config)
    _, issuer, _ = _keys(cfg)
    tok = TokenIssuer(issuer, audience=cfg.public_url, default_ttl=a.ttl).issue(a.name, a.scopes.split(","))
    print(f"registered {a.name}; bearer token (ttl {a.ttl}s):\n{tok}")


def cmd_token(a: argparse.Namespace) -> None:
    cfg = Config.load(a.config)
    _, issuer, _ = _keys(cfg)
    print(TokenIssuer(issuer, audience=cfg.public_url, default_ttl=a.ttl).issue(a.subject, a.scopes.split(",")))


def cmd_serve(a: argparse.Namespace) -> None:
    import uvicorn

    from qudisclose.server import build_server, http_app

    cfg = Config.load(a.config)
    server, issuer, audit_id = _keys(cfg)
    store = _store(cfg)
    audit = AuditLog(store.db, audit_id)
    orch = _orchestrator(cfg, store, audit)
    mcp = build_server(config=cfg, orchestrator=orch, audit=audit, server_identity=server, issuer_identity=issuer, keyring=_keyring(cfg))
    print(f"qudisclose MCP server on {cfg.public_url}  (provider={cfg.provider}, repos={list(cfg.repos)}, "
          f"webhooks={list(cfg.webhook_secrets) or 'off'})")
    uvicorn.run(http_app(mcp, cfg, orch), host=cfg.host, port=cfg.port, log_level="info")


def cmd_ingest(a: argparse.Namespace) -> None:
    from qudisclose.ingest import DependabotSource, GitHubAdvisorySource, OSVSource, PollingIngestor
    from qudisclose.ingest.base import default_fetch
    from qudisclose.ingest.osv import default_post

    cfg = Config.load(a.config)
    _, _, audit_id = _keys(cfg)
    store = _store(cfg)
    orch = _orchestrator(cfg, store, AuditLog(store.db, audit_id))
    token = os.environ.get(cfg.github_token_env)
    repos = list(cfg.repos)
    fetch = default_fetch()
    sources = [GitHubAdvisorySource(repos, token, fetch), DependabotSource(repos, token, fetch),
               OSVSource([(r.ecosystem, r.package, slug) for slug, r in cfg.repos.items() if r.ecosystem and r.package], default_post())]

    def sink(report):
        rep, new = orch.intake(report, actor="ingest")
        print(f"{'NEW' if new else 'dup'} {rep.id} [{report.source}] {report.submission.title[:70]}")
        if new and not a.no_run:
            orch.run_case(rep.id)

    print(PollingIngestor(sources, sink).run_once())


def cmd_run(a: argparse.Namespace) -> None:
    cfg = Config.load(a.config)
    _, _, audit_id = _keys(cfg)
    store = _store(cfg)
    orch = _orchestrator(cfg, store, AuditLog(store.db, audit_id))
    r = orch.run_case(a.report_id)
    print(json.dumps({"report_id": r.id, "status": r.status, "slo": [c.model_dump() for c in orch.slo_checks(r)]}, indent=2, default=str))


def cmd_status(a: argparse.Namespace) -> None:
    cfg = Config.load(a.config)
    store = _store(cfg)
    if a.report_id:
        r = store.get_report(a.report_id)
        if not r:
            sys.exit("unknown report")
        print(json.dumps({"report": r.model_dump(mode="json"), "events": [e.model_dump(mode="json") for e in store.events(r.id)],
                          "artifacts": store.artifacts(r.id)}, indent=2, default=str))
    else:
        for r in store.list_reports():
            print(f"{r.id}  {r.status:12} {r.severity or '-':8} {r.lane or '-':9} {r.source:15} {r.submission.title[:60]}")


def cmd_dashboard(a: argparse.Namespace) -> None:
    from qudisclose.dashboard import serve
    cfg = Config.load(a.config)
    serve(_store(cfg), cfg, host=a.host, port=a.port)


def cmd_audit(a: argparse.Namespace) -> None:
    cfg = Config.load(a.config)
    _, _, audit_id = _keys(cfg)
    store = _store(cfg)
    log = AuditLog(store.db, audit_id)
    ok, msg = log.verify_chain()
    print(f"chain: {'OK' if ok else 'BROKEN'} ({msg}); {len(log.entries())} entries")
    if a.show:
        for e in log.entries(a.show if a.show != "all" else None):
            print(f"{e['seq']:5} {e['at']} {e['actor']:24} {e['action']:28} {e['report_id'] or ''}")
    sys.exit(0 if ok else 1)


def cmd_control(a: argparse.Namespace) -> None:
    cfg = Config.load(a.config)
    _, _, audit_id = _keys(cfg)
    store = _store(cfg)
    orch = _orchestrator(cfg, store, AuditLog(store.db, audit_id))
    actor = f"cli:{os.environ.get('USER', 'operator')}"
    fn = {"pause": lambda: orch.pause(a.report_id, actor, a.reason or ""), "resume": lambda: orch.resume(a.report_id, actor),
          "approve": lambda: orch.approve_release(a.report_id, actor), "disclose": lambda: orch.disclose(a.report_id, actor)}[a.action]
    r = fn()
    print(f"{r.id} -> {r.status} (paused={r.paused})")


def cmd_submit(a: argparse.Namespace) -> None:
    from qudisclose.client import ReporterClient

    sub = ReportSubmission.model_validate(json.loads(Path(a.file).read_text()))
    ident = Identity.load(Path(a.key))

    async def go():
        async with ReporterClient(a.url, a.token, ident, pinned_fingerprint=a.pin) as c:
            print(f"catalog fingerprint {c.fingerprint}")
            res = await c.submit(sub)
            print(json.dumps(res, indent=2))
            if a.wait:
                import time
                for _ in range(a.wait):
                    st = await c.status(res["report_id"])
                    print(f"  status={st['status']}")
                    if st["status"] in ("closed", "rejected", "failed", "paused"):
                        print(json.dumps(await c.postmortem(res["report_id"]), indent=2))
                        break
                    time.sleep(2)
    asyncio.run(go())


def cmd_sign(a: argparse.Namespace) -> None:
    """Print a signed envelope for a tool call, for MCP clients that cannot set _meta (pass it as the `envelope` argument)."""
    from qudisclose.security import SignedEnvelope

    args = json.loads(Path(a.args_file).read_text()) if a.args_file else json.loads(sys.stdin.read())
    env = SignedEnvelope.create(Identity.load(Path(a.key)), a.tool, args, ttl=a.ttl)
    print(json.dumps(env.model_dump(), indent=2))


def cmd_hunt(a: argparse.Namespace) -> None:
    """Always-on red-team loop: look at the codebase feature by feature, prove reproducible bugs, escalate them."""
    from qudisclose.hunter import Hunter, LocalEscalator, McpEscalator

    cfg = Config.load(a.config)
    _, _, audit_id = _keys(cfg)
    store = _store(cfg)
    orch = _orchestrator(cfg, store, AuditLog(store.db, audit_id))
    repo_slug = a.repo or (next(iter(cfg.repos)) if cfg.repos else None)
    if not repo_slug or repo_slug not in cfg.repos:
        sys.exit(f"repo {repo_slug!r} is not configured; add it with `qudisclose init --repo ... --path ...`")
    repo_cfg = cfg.repos[repo_slug]

    if cfg.provider == "scripted":
        from qudisclose.demo import demo_provider_with_hunter
        provider = demo_provider_with_hunter()
        model_label = "scripted"
    else:
        from qudisclose.agents.provider import OpenAICompatProvider
        hc = cfg.hunter
        model_label = a.model or hc.model
        provider = OpenAICompatProvider(base_url=a.endpoint or hc.endpoint, model=model_label,
                                        api_key=os.environ.get(hc.api_key_env, "ollama"), temperature=hc.temperature)

    submit = a.submit or cfg.hunter.submit
    if submit == "mcp":
        hc = cfg.hunter
        if not (hc.mcp_url or cfg.public_url) or not hc.mcp_key_path:
            sys.exit("mcp submission needs hunter.mcp_url and hunter.mcp_key_path in the config")
        escalator = McpEscalator(hc.mcp_url or cfg.public_url, os.environ[hc.mcp_token_env], hc.mcp_key_path,
                                 pinned_server_key=hc.pinned_server_key, pinned_fingerprint=hc.pinned_fingerprint)
    else:
        escalator = LocalEscalator(orch)

    def report(o: Any) -> None:
        tag = f"ESCALATED -> {o.report_id}" if o.escalated else o.reason
        print(f"[hunt] {o.path or '-':44} {tag}")

    try:
        h = Hunter(provider=provider, store=store, repo_slug=repo_slug, repo_path=repo_cfg.path,
                   escalator=escalator, sandbox_config=cfg.sandbox, effort=cfg.hunter.effort, on_outcome=report,
                   authorized_targets=cfg.hunter.authorized_targets, authorization_basis=cfg.hunter.authorization_basis)
    except PermissionError as exc:
        sys.exit(str(exc))
    print(f"hunting {repo_slug} with {model_label} (iterations={a.iterations or 'infinite'}, "
          f"interval={a.interval}s, submit={submit}); Ctrl-C to stop")
    try:
        h.run(iterations=a.iterations, interval=a.interval, max_findings=a.max_findings)
    except KeyboardInterrupt:
        print("\nstopping; draining in-flight cases...")
    finally:
        if isinstance(escalator, LocalEscalator):
            orch.wait_all()  # let escalated cases finish before the process exits (bounded/interrupted runs)


def cmd_infer_bridge(a: argparse.Namespace) -> None:
    """Serve the authenticated bridge in front of local Ollama (see `inference` in the config).

    Then expose it with a tunnel, e.g. `ngrok http <bridge_port>`, and point in-sandbox consumers at
    the tunnel URL with a token. Only code runs in the sandbox; inference stays on this host."""
    import os

    from qudisclose.inference.bridge import serve

    cfg = Config.load(a.config)
    static = os.environ.get(cfg.inference.static_token_env) or None
    if not cfg.inference.oidc_issuer and not static:
        print(f"refusing to start: no bridge auth configured. Set inference.oidc_issuer, or export "
              f"${cfg.inference.static_token_env} with a shared secret.")
        raise SystemExit(2)
    serve(cfg.inference, static_token=static)


def cmd_attest(a: argparse.Namespace) -> None:
    """Print the VSLA statements (and receipt / verification) recorded for a case."""
    cfg = Config.load(a.config)
    store = _store(cfg)
    r = store.get_report(a.report_id)
    if not r:
        sys.exit("unknown report")
    arts = store.artifacts(r.id)
    out = {"report_id": r.id, "vsla": r.vsla, **{k: v for k, v in arts.items() if k.startswith("vsla_")}}
    print(json.dumps(out, indent=2, default=str))


def cmd_verify_attestation(a: argparse.Namespace) -> None:
    """Verify a VSLA statement file against this deployment's pinned keys (reporters, server, countersigners, providers,
    roots) and expectations, and print the claimed and verified levels with every check and its kind. Missing inputs fail
    the checks that need them (VSLA-V-3): without --ledger Identity stops at L1, without --receipt/--reexec Evidence does."""
    from qudisclose import __version__
    from qudisclose.vsla import Verifier
    from qudisclose.vsla.attest import harness_digest
    from qudisclose.vsla.environment import NoEnvironment, SignedQuoteEnvironment
    from qudisclose.vsla.verify import vsla_keyring

    cfg = Config.load(a.config)
    server, _, _ = _keys(cfg)
    host = cfg.public_url.split("//", 1)[-1].split("/", 1)[0]
    v = cfg.vsla
    ring = vsla_keyring(reporters=cfg.trusted_reporters, platform=server, platform_name=host, roots=v.trusted_roots, countersigners=v.pinned_countersigners,
                        providers=v.trusted_providers, operators=v.trusted_operators)
    for extra in a.key or []:
        ident = Identity.load(extra)
        ring.add(f"finder:{ident.name}", ident)
    env = SignedQuoteEnvironment(v.environment_evidence_path) if v.environment_evidence_path else NoEnvironment()
    load = lambda p: json.loads(Path(p).read_text()) if p else None
    expectations = {"harness": {"qudisclose": {__version__: harness_digest()["sha256"]}}, "measurements": []}
    for extra_exp in (load(a.expectations), load(v.expectations_path) if v.expectations_path and Path(v.expectations_path).exists() else None):
        if extra_exp:
            for name, versions in (extra_exp.get("harness") or {}).items():
                expectations["harness"].setdefault(name, {}).update(versions)
            expectations["measurements"].extend(extra_exp.get("measurements") or [])
    verifier = Verifier(ring, platform_keyid=f"platform:{host}", environment=env, expectations=expectations, floor=v.floor, min_entries=v.min_entries,
                        min_countersigners=v.min_countersigners, min_age_days=v.min_age_days, require_leaves=v.require_leaves)
    bundle = load(a.statement)
    envelope = bundle.get("statement", bundle) if isinstance(bundle, dict) and "statement" in bundle else bundle
    last = None
    if a.last_seen:
        r, c = a.last_seen.rsplit(":", 1)
        last = (r, int(c))
    ledger = load(a.ledger) if a.ledger else (bundle.get("ledger") if isinstance(bundle, dict) else None)
    res = verifier.verify(envelope, report=load(a.report), leaves=load(a.leaves) or (bundle.get("leaves") if isinstance(bundle, dict) else None),
                          receipt=load(a.receipt), reexecution=load(a.reexec), ledger_entries=ledger, last_seen=last, expected_intake=cfg.public_url)
    print(json.dumps(res.to_dict(), indent=2))
    print(f"VSLA {res.track}: claimed L{res.claimed}, verified L{res.verified}", file=sys.stderr)


def cmd_demo(a: argparse.Namespace) -> None:
    """End-to-end offline demo against fixtures/vulnpkg with the scripted provider."""
    import shutil
    import tempfile

    from qudisclose.demo import FIXTURE, demo_provider, demo_reporter, demo_submission
    from qudisclose.models import Report, Source
    from qudisclose.orchestrator import Orchestrator
    from qudisclose.publisher import LocalPublisher

    work = Path(tempfile.mkdtemp(prefix="qud-demo-"))
    repo = work / "vulnpkg"
    shutil.copytree(FIXTURE, repo)
    cfg = Config(db_dsn="sqlite:///" + str(work / "demo.db"), out_dir=str(work / "out"), provider="scripted",
                 repos={"example/vulnpkg": RepoConfig(path=str(repo), test_command="python -m pytest -q")})
    cfg.vsla.allow_ephemeral_platform_key = True   # a demo: receipts signed here verify nowhere else, and the policy says so
    store = _store(cfg)
    audit = AuditLog(store.db, Identity.generate("audit"))
    orch = Orchestrator(store=store, audit=audit, config=cfg, provider=demo_provider(), publisher=LocalPublisher(cfg.out_dir))
    print("VSLA: qudisclose attests every case it verifies (embargoed + published profiles); this run's statements land in out/<case>/vsla.*.json")
    rep, _ = orch.intake(Report.from_submission(demo_submission(), source=Source.MCP, reporter=demo_reporter()), actor="agent:researcher-1")
    print(f"intake -> {rep.id} acknowledged")
    r = orch.run_case(rep.id)
    print(f"final status: {r.status}")
    for e in store.events(r.id):
        print(f"  {e.at:%H:%M:%S.%f} {e.kind:24} {e.actor:14} {json.dumps(e.data, default=str)[:90]}")
    print("\nSLO checks:")
    for c in orch.slo_checks(r):
        print(f"  {c.name:16} target {c.target_minutes:>5} min  actual {c.actual_minutes!s:>8}  met={c.met}")
    pm = store.get_artifact(r.id, "postmortem")
    print("\nPOSTMORTEM\n  went well:  " + "\n              ".join(pm["went_well"]) + "\n  went badly: " + "\n              ".join(pm["went_badly"])
          + "\n  actions:    " + "\n              ".join(pm["action_items"]))
    ok, msg = audit.verify_chain()
    print(f"\naudit chain: {'OK' if ok else 'BROKEN'} ({len(audit.entries())} entries)  outputs in {cfg.out_dir}/{r.id}/")
    if r.vsla:
        from qudisclose.vsla.dsse import envelope_payload
        arts = store.artifacts(r.id)
        pf = envelope_payload(arts["vsla_finding"])["predicate"] if arts.get("vsla_finding") else {}
        pp = envelope_payload(arts["vsla_patch"])["predicate"] if arts.get("vsla_patch") else {}
        print(f"VSLA: finding claimed L{r.vsla.get('finding', {}).get('claimed', '-')} · patch claimed L{r.vsla.get('patch', {}).get('claimed', '-')} "
              f"· profile {pf.get('profile', '-')} · authorization {pf.get('authorization', {}).get('basis', '-')} "
              f"· sandbox {pf.get('reproduction', {}).get('sandbox', {}).get('backend', '-')}/{pf.get('reproduction', {}).get('sandbox', {}).get('isolation', '-')} "
              f"· patch scope {pp.get('patch', {}).get('scope', '-')}")
        led = r.vsla.get("ledger", {})
        print(f"VSLA: reporter ledger outcomes {led.get('outcomes', {})} · score {orch.ledger.score(orch.finder_id(rep.reporter.identity, rep.reporter.public_key), 'finding')['score']} "
              f"(platform key is ephemeral in the demo; a real deployment refuses to start that way)")


def main(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser(prog="qudisclose", description=__doc__)
    p.add_argument("--config", default=os.environ.get("QUDISCLOSE_CONFIG", "qudisclose.json"))
    sp = p.add_subparsers(dest="cmd", required=True)

    s = sp.add_parser("init", help="write config + generate server/issuer/audit keys"); s.set_defaults(fn=cmd_init)
    s.add_argument("--repo", help="owner/name"); s.add_argument("--path", help="local checkout")
    s.add_argument("--test-command", default="python -m pytest -q"); s.add_argument("--provider", default="anthropic", choices=["anthropic", "scripted"])

    s = sp.add_parser("register-reporter", help="pin a reporter identity and mint its token"); s.set_defaults(fn=cmd_register_reporter)
    s.add_argument("name"); s.add_argument("--public-key"); s.add_argument("--generate", metavar="DIR", help="generate a key pair into DIR instead")
    s.add_argument("--scopes", default="report:submit,report:read"); s.add_argument("--ttl", type=int, default=30 * 24 * 3600)

    s = sp.add_parser("token", help="mint a scoped bearer token"); s.set_defaults(fn=cmd_token)
    s.add_argument("subject"); s.add_argument("--scopes", default="report:read"); s.add_argument("--ttl", type=int, default=3600)

    s = sp.add_parser("serve", help="run the MCP intake server"); s.set_defaults(fn=cmd_serve)
    s = sp.add_parser("ingest", help="poll GitHub advisories, Dependabot and OSV once"); s.set_defaults(fn=cmd_ingest); s.add_argument("--no-run", action="store_true")
    s = sp.add_parser("run", help="run the pipeline for a report"); s.set_defaults(fn=cmd_run); s.add_argument("report_id")
    s = sp.add_parser("status", help="list cases or show one"); s.set_defaults(fn=cmd_status); s.add_argument("report_id", nargs="?")
    s = sp.add_parser("dashboard", help="serve a read-only web view of the store"); s.set_defaults(fn=cmd_dashboard)
    s.add_argument("--host", default="127.0.0.1"); s.add_argument("--port", type=int, default=8780)
    s = sp.add_parser("audit", help="verify the audit chain"); s.set_defaults(fn=cmd_audit); s.add_argument("--show", metavar="REPORT_ID|all")
    s = sp.add_parser("control", help="pause / resume / approve / disclose a case"); s.set_defaults(fn=cmd_control)
    s.add_argument("action", choices=["pause", "resume", "approve", "disclose"]); s.add_argument("report_id"); s.add_argument("--reason")
    s = sp.add_parser("submit", help="submit a report as a reporter agent (client side)"); s.set_defaults(fn=cmd_submit)
    s.add_argument("file", help="JSON matching ReportSubmission"); s.add_argument("--url", default="http://127.0.0.1:8765/mcp")
    s.add_argument("--token", required=True); s.add_argument("--key", required=True, help="reporter identity json"); s.add_argument("--pin", help="pinned catalog fingerprint")
    s.add_argument("--wait", type=int, default=0, help="poll status up to N times")
    s = sp.add_parser("sign", help="print a signed envelope for a tool call (for generic MCP clients)"); s.set_defaults(fn=cmd_sign)
    s.add_argument("tool"); s.add_argument("args_file", nargs="?", help="JSON file with the tool arguments (default: stdin)")
    s.add_argument("--key", required=True, help="identity json with a private key"); s.add_argument("--ttl", type=int, default=120)
    s = sp.add_parser("hunt", help="always-on red-team loop: find reproducible bugs and escalate them")
    s.set_defaults(fn=cmd_hunt)
    s.add_argument("--repo", help="owner/name (default: the first configured repo)")
    s.add_argument("--iterations", type=int, default=0, help="0 = loop forever")
    s.add_argument("--interval", type=float, default=30.0, help="seconds between cycles")
    s.add_argument("--max-findings", type=int, default=0, dest="max_findings", help="stop after N escalations (0 = unlimited)")
    s.add_argument("--endpoint", help="override the self-hosted OpenAI-compatible endpoint")
    s.add_argument("--model", help="override the hunter model")
    s.add_argument("--submit", choices=["local", "mcp"], help="in-process (local) or signed over MCP")
    s = sp.add_parser("infer-bridge", help="serve the authenticated bridge in front of local Ollama")
    s.set_defaults(fn=cmd_infer_bridge)
    s.add_argument("action", nargs="?", choices=["serve"], default="serve")
    s = sp.add_parser("attest", help="print the VSLA statements recorded for a case"); s.set_defaults(fn=cmd_attest); s.add_argument("report_id")
    s = sp.add_parser("verify-attestation", help="verify a VSLA statement (DSSE envelope or bundle) and print claimed vs verified level")
    s.set_defaults(fn=cmd_verify_attestation); s.add_argument("statement"); s.add_argument("--report"); s.add_argument("--leaves")
    s.add_argument("--receipt"); s.add_argument("--reexec"); s.add_argument("--key", action="append", help="extra finder identity json to trust")
    s.add_argument("--ledger", help="json list of the finder's countersigned ledger entries (DSSE envelopes)")
    s.add_argument("--expectations", help="json {harness: {name: {version: sha256}}, measurements: [...]} (VSLA-V-6)")
    s.add_argument("--last-seen", dest="last_seen", help="ROOT:COUNT of this finder's ledger as you last saw it (VSLA-P-14)")
    s = sp.add_parser("demo", help="offline end-to-end demo"); s.set_defaults(fn=cmd_demo)

    a = p.parse_args(argv)
    a.fn(a)


if __name__ == "__main__":
    main()
