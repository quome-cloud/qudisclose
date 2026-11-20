# NSA MCP guidance → qudisclose controls

Source: NSA Artificial Intelligence Security Center, *Model Context Protocol (MCP): Security Design
Considerations for AI-Driven Automation*, Cybersecurity Information Sheet U/OO/6030316-26 (PP-26-1834),
Version 1.0, 20 May 2026. <https://www.nsa.gov/Portals/75/documents/Cybersecurity/CSI_MCP_SECURITY.pdf>

The CSI frames MCP deployments as a *continuum* in which model, client, server and tools share one effective
trust domain, and lists design considerations rather than a checklist. The table maps each consideration to
the code that implements it and the test that proves it.

| NSA design consideration | Threat it addresses | Where in qudisclose | Test |
|---|---|---|---|
| Cryptographic integrity of every MCP message at the protocol layer (TLS is not sufficient) | tampering by intermediaries, replay | `security/envelope.py` `SignedEnvelope` (Ed25519 over `{sender, tool, args_hash, nonce, iat, exp}`, carried in `_meta["qudisclose/sig"]`); `server.GuardMiddleware` enforces on every mutating tool | `test_security.py::test_envelope_*`, `test_server.py::test_submit_requires_signed_envelope_*` |
| Replay protection with nonces and expiry | session replay | `NonceCache`, 120 s default TTL, 30 s skew window | same |
| Least privilege at the tool-call boundary; no ambient authority | agent misuse, confused deputy | `server.TOOL_SCOPES` (one scope per tool), EdDSA JWTs with audience + short TTL (`security/tokens.py`), `MCPError` on missing scope | `test_tokens_*`, `test_submit_requires_*` |
| Credential brokering; agents never hold long-lived keys | credential theft via injected context | `security/broker.py` `CredentialBroker` / `CredentialLease` (purpose + repo + holder + TTL); `publisher.GitHubPublisher` takes a separate lease for the PR and for the advisory and revokes each after use | `test_broker_*`, `test_human_approval_gate_for_publish` |
| Distinct non-human identities, individually rate-limited and revocable | lateral movement, attribution loss | `security/keys.py` `Identity` per agent/reporter/server; `RateLimiter` per identity; `TokenIssuer.revoke` | `test_identity_roundtrip`, `test_rate_limiter`, `test_tokens_*` |
| Tamper-evident audit trail covering invocation context, tool inputs and outputs, stored where agents cannot modify it | unaccountable actions | `security/audit.py` `AuditLog` (hash chain + Ed25519 signature, inputs and outputs, secrets redacted first); the agents have no handle to the signing key | `test_audit_chain_detects_tampering`, `get_audit_trail` tool |
| Trust chain: verify the gateway/server before routing; pin keys | rogue server | server signs its catalog fingerprint with its identity key; `client.ReporterClient.verify_trust` pins server key | `test_reporter_client_trust_checks` |
| Tool inventory pinning / scrutiny of tool catalogs (treat tools as dependencies) | rug-pull, definition drift, name collision | `security/catalog.py` `catalog_fingerprint`; `catalog_fingerprint` tool; client refuses to operate on drift | `test_catalog_fingerprint_*`, `test_reporter_client_trust_checks` |
| Tool output and third-party text are untrusted input; detect indirect prompt injection | indirect prompt injection, tool-chain pivots | `security/scanner.py` `InjectionScanner`, `wrap_untrusted` envelope on every report / diff / test output before it reaches a model; `TriageResult.injection_suspected` | `test_scanner_*`, `test_injection_in_report_is_flagged_and_wrapped` |
| Strict validation before deserialization | serialization risk | every tool input is a pydantic model with `extra="forbid"` and length caps (`models.Strict`); webhook payloads must match the schema exactly | `test_signed_webhook_roundtrip_and_rejections` |
| Per-execution sandboxing / OS-level containment | arbitrary code execution from PoCs or patches | `security/sandbox.py` `Sandbox`: a checkout per case with its own `.git` (nothing but objects shared with the repository; platform git calls confined, hooks off), scrubbed env, rlimits, `unshare -n` on Linux, proxy poisoning elsewhere, path confinement, command allowlist (`agents/tools.py`) | exercised by every orchestrator test |
| Outbound filtering / DLP | data egress, embargo leaks | `Redactor` on everything logged or sent to a model; `ingest.base.default_fetch` egress allowlist | `test_scanner_redactor_and_wrapper` |
| Policy enforcement at the tool layer with human-in-the-loop for sensitive operations | irreversible actions | `pause_case` / `resume_case` / `approve_release` admin tools; `Policy.require_human_for_merge/publish` gate the broker | `test_pause_halts_pipeline_*`, `test_human_approval_gate_for_publish` |
| Verification independent of the model's claims | agent misuse / hallucinated success | the orchestrator re-runs the failing test on the vulnerable tree and verifies every patch in a *clean* worktree (`Orchestrator._verify_patch`); the reviewer sees only report + diff + test output | `test_unverified_patch_is_retried_then_fails`, `test_full_pipeline_*` |

## Production deployment notes (not enforced by code)

- Run the server container-per-deployment behind TLS; the signed envelopes are defence in depth, not a TLS
  replacement.
- Mount the audit database on storage the agent processes cannot write to directly (e.g. a separate
  service account), and ship `audit` rows to your SIEM.
- Replace `CredentialBroker._fetch_from_env` with a GitHub App installation-token minting call so leases are
  genuinely short-lived at the issuer, not only in the process.
- Linux hosts get network namespaces for sandboxed commands via `unshare -n`; on macOS the sandbox relies on
  proxy poisoning and rlimits only. Use Linux in production.
