import pytest
from mcp import Client

from mcp.shared.exceptions import MCPError

from qudisclose.client import TrustError
from qudisclose.demo import demo_submission
from qudisclose.security import Identity, SignedEnvelope, catalog_fingerprint
from qudisclose.security.keys import KeyRing
from qudisclose.server import META_SIG_KEY, build_server


async def denied(c, name, args, meta=None) -> str:
    """Call a tool expecting a protocol-level denial; return the error message."""
    with pytest.raises(MCPError) as ei:
        await c.call_tool(name, args, meta=meta)
    return ei.value.message


@pytest.fixture
def served(env):
    cfg, store, audit, provider, orch = env
    reporter = Identity.generate("agent:researcher-1")
    ring = KeyRing(); ring.add(reporter)
    current = {"identity": "agent:researcher-1", "scopes": {"report:submit", "report:read"}}
    mcp = build_server(config=cfg, orchestrator=orch, audit=audit, server_identity=Identity.generate("server"),
                       issuer_identity=Identity.generate("issuer"), keyring=ring, enable_http_auth=False,
                       identity_resolver=lambda: (current["identity"], set(current["scopes"])))
    return mcp, reporter, current, orch, store


async def test_catalog_fingerprint_is_signed_and_matches_live_catalog(served):
    mcp, reporter, current, orch, store = served
    async with Client(mcp) as c:
        tools = (await c.list_tools()).tools
        res = await c.call_tool("catalog_fingerprint", {})
        fp = res.structured_content["fingerprint"]
        assert fp == catalog_fingerprint(tools)
        srv = Identity.from_public_hex(res.structured_content["server"], res.structured_content["server_public_key"])
        assert srv.verify(bytes.fromhex(res.structured_content["signature"]), fp.encode())
        names = {t.name for t in tools}
        assert {"submit_report", "get_report_status", "pause_case", "get_postmortem", "get_audit_trail"} <= names


async def test_submit_requires_signed_envelope_scope_and_matching_identity(served):
    mcp, reporter, current, orch, store = served
    args = {"report": demo_submission().model_dump(exclude_none=True)}
    async with Client(mcp) as c:
        assert "signed envelope" in await denied(c, "submit_report", args)
        env = SignedEnvelope.create(reporter, "submit_report", args).model_dump()
        res = await c.call_tool("submit_report", args, meta={META_SIG_KEY: env})
        assert not res.is_error, res.content
        rid = res.structured_content["report_id"]
        assert res.structured_content["new"] is True
        # replaying the same envelope is rejected
        assert "replayed" in await denied(c, "submit_report", args, {META_SIG_KEY: env})
        # fresh envelope, same content -> idempotent duplicate
        env2 = SignedEnvelope.create(reporter, "submit_report", args).model_dump()
        res = await c.call_tool("submit_report", args, meta={META_SIG_KEY: env2})
        assert res.structured_content["report_id"] == rid and res.structured_content["new"] is False
        # scope enforcement
        current["scopes"] = {"report:read"}
        env3 = SignedEnvelope.create(reporter, "submit_report", args).model_dump()
        assert "scope report:submit" in await denied(c, "submit_report", args, {META_SIG_KEY: env3})
        # admin tool denied to reporter even with a valid envelope
        current["scopes"] = {"report:submit", "report:read"}
        pargs = {"query": {"report_id": rid, "reason": "x"}}
        assert "scope admin" in await denied(c, "pause_case", pargs, {META_SIG_KEY: SignedEnvelope.create(reporter, "pause_case", pargs).model_dump()})
        # identity mismatch: bearer says someone else
        current["identity"] = "agent:impostor"
        env4 = SignedEnvelope.create(reporter, "submit_report", args).model_dump()
        assert "does not match bearer" in await denied(c, "submit_report", args, {META_SIG_KEY: env4})
    orch.wait_all()


async def test_status_resources_and_embargo_hide_details_until_published(served):
    mcp, reporter, current, orch, store = served
    args = {"report": demo_submission().model_dump(exclude_none=True)}
    async with Client(mcp) as c:
        res = await c.call_tool("submit_report", args, meta={META_SIG_KEY: SignedEnvelope.create(reporter, "submit_report", args).model_dump()})
        rid = res.structured_content["report_id"]
        orch.wait_all()  # let the scheduled case finish
        st = await c.call_tool("get_report_status", {"query": {"report_id": rid}})
        assert st.structured_content["status"] == "closed", (st.structured_content["timeline"], store.artifacts(rid).get("postmortem", {}).get("went_badly"), [e.data for e in store.events(rid) if e.kind in ("error", "patch_attempt", "reproduction_unverified")])
        assert any(s["name"] == "acknowledge" and s["met"] for s in st.structured_content["slo"])
        adv = await c.call_tool("get_advisory", {"query": {"report_id": rid}})
        assert adv.structured_content["available"] and not adv.structured_content["embargoed"]
        pm = await c.call_tool("get_postmortem", {"query": {"report_id": rid}})
        assert pm.structured_content["postmortem"]["went_well"]
        trail = await c.call_tool("get_audit_trail", {"query": {"report_id": rid}})
        assert trail.structured_content["chain_ok"] and all("input" not in e for e in trail.structured_content["entries"])
        pol = await c.read_resource("qudisclose://policy")
        assert "embargo_days_max" in pol.contents[0].text
        lst = await c.call_tool("list_reports", {"query": {}})
        assert lst.structured_content["reports"][0]["report_id"] == rid
        # resources require report:read
        current["scopes"] = set()
        with pytest.raises(MCPError, match="report:read"):
            await c.read_resource("qudisclose://policy")


async def test_reporter_client_trust_checks(served, monkeypatch):
    """Drive ReporterClient's trust logic against the in-memory server by swapping its transport."""
    from qudisclose import client as climod
    mcp, reporter, current, orch, store = served

    async with Client(mcp) as c:
        rc = climod.ReporterClient("mem://", "tok", reporter)
        rc._client = c
        fp = await rc.verify_trust()
        assert fp == catalog_fingerprint((await c.list_tools()).tools)
        rc.pinned_fingerprint = "0" * 64
        with pytest.raises(TrustError, match="catalog changed"):
            await rc.verify_trust()
        rc.pinned_fingerprint = None
        rc.pinned_server_key = Identity.generate("evil").public_hex
        with pytest.raises(TrustError, match="identity key"):
            await rc.verify_trust()
        rc.pinned_server_key = None
        out = await rc.submit(demo_submission())
        assert out["report_id"].startswith("rpt_")
    orch.wait_all()


async def test_envelope_accepted_as_argument_for_generic_clients(served):
    mcp, reporter, current, orch, store = served
    args = {"report": demo_submission().model_dump(exclude_none=True)}
    async with Client(mcp) as c:
        env = SignedEnvelope.create(reporter, "submit_report", args).model_dump()
        res = await c.call_tool("submit_report", {**args, "envelope": env})
        assert not res.is_error, res.content
        assert res.structured_content["new"] is True
        # the envelope must match the OTHER arguments; swapping the report after signing is rejected
        other = {"report": {**args["report"], "title": "A different report title entirely"}}
        assert "arguments do not match" in await denied(c, "submit_report", {**other, "envelope": SignedEnvelope.create(reporter, "submit_report", args).model_dump()})
        schema = next(t for t in (await c.list_tools()).tools if t.name == "submit_report").input_schema
        assert "envelope" in schema["properties"]
    orch.wait_all()


def test_webhook_intake_route(env):
    import json
    from qudisclose.ingest import SignedWebhookSource
    from qudisclose.server import handle_webhook
    cfg, store, audit, provider, orch = env
    src = SignedWebhookSource({"huntr": "s3cret"})
    body = json.dumps({"external_id": "H-9", **demo_submission().model_dump(exclude_none=True)}).encode()
    sig, ts = SignedWebhookSource.sign("s3cret", body)
    status, out = handle_webhook(orch, src, sender="huntr", body=body, headers={"x-qud-signature": sig, "x-qud-timestamp": ts})
    assert status == 202 and out["new"] is True and out["report_id"].startswith("rpt_")
    status, out = handle_webhook(orch, src, sender="huntr", body=body + b" ", headers={"x-qud-signature": sig, "x-qud-timestamp": ts})
    assert status == 401
    status, out = handle_webhook(orch, src, sender="nobody", body=body, headers={"x-qud-signature": sig, "x-qud-timestamp": ts})
    assert status == 401
    orch.wait_all()
    assert any(e["action"] == "webhook.rejected" for e in audit.entries())
