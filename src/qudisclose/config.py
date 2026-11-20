"""Deployment configuration (JSON file, default ./qudisclose.json)."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from qudisclose.policy import Policy


class RepoConfig(BaseModel):
    path: str = Field(description="local checkout the sandboxes are created from")
    test_command: str = "python -m pytest -q"
    default_branch: str = "main"
    ecosystem: str | None = Field(default=None, description="OSV ecosystem, e.g. PyPI, npm, Go")
    package: str | None = None


class HunterConfig(BaseModel):
    """Always-on red-team hunter. The model is self-hosted (Ollama/vLLM/llama.cpp serving GLM or Qwen);
    source never leaves your hardware.

    `authorized_targets` is the allowlist of repositories (owner/name slugs, repo URLs or local checkout paths) the
    hunter may run against; it refuses to start for anything else. VSLA records the authorization basis in every
    statement (VSLA-F-19) but cannot enforce it: this allowlist is the operator's own guard."""

    enabled: bool = False
    endpoint: str = "http://localhost:11434/v1"          # OpenAI-compatible endpoint of the self-hosted node
    model: str = "qwen3.8:27b"
    api_key_env: str = "QUDISCLOSE_HUNTER_KEY"           # Ollama ignores it; any value works
    temperature: float = 0.2
    interval_seconds: int = 30
    max_findings: int = 0                                 # 0 = unlimited
    effort: str = "high"
    submit: str = "local"                                 # "local" (in-process) or "mcp" (signed, over the wire)
    mcp_url: str | None = None
    mcp_token_env: str = "QUDISCLOSE_HUNTER_TOKEN"
    mcp_key_path: str | None = None                       # reporter identity json for the hunter
    pinned_server_key: str | None = None
    pinned_fingerprint: str | None = None
    authorized_targets: list[str] = Field(default_factory=list, description="repos (owner/name, URL or local path) the hunter may test; empty = refuse to start")
    authorization_basis: str = Field(default="ownership", description="ownership | program | engagement | safe-harbour (VSLA-F-19)")


class SandboxConfig(BaseModel):
    """Where the reproducer/patcher/hunter run untrusted code. `local` is a per-case checkout (own `.git`) + rlimits +
    `unshare -n` on this host (default; the test path; VSLA isolation class `process`, a development convenience).
    `quome` runs each case in an isolated Quome sandbox VM (egress killswitch, east-west guard, metadata guard) over
    Quome's public API (isolation class `vm`, what VSLA-P-11 requires of a production intake); with a self-hosted
    Quome sandbox host, source still never leaves your hardware."""

    backend: str = "local"                                # "local" | "quome"
    quome_api_key_env: str = "QUOME_API_KEY"              # env var holding the Quome API key (SDK default)
    quome_base_url: str | None = None                     # override the SDK's default base URL
    quome_org_id: str | None = None                       # org id; else the SDK resolves it from the key
    quome_template: str = "Code Write"                    # template name or id (SDK resolves names)
    quome_sandbox_id: str | None = None                   # attach to this existing sandbox instead of creating one
    repo_subdir: str = "repo"                             # case files live under /workspace/qudisclose/<case>/<repo_subdir>
    create_timeout_seconds: int = 300                     # wait-until-running budget
    exec_timeout_seconds: int = 240                       # SDK runs <=240s synchronously; above that it uses an async job


class InferenceConfig(BaseModel):
    """The self-hosted, OpenAI-compatible inference endpoint (Ollama/vLLM on your Mac Studio) and the
    optional authenticated bridge that exposes it to remote consumers.

    Inference always runs locally — the agents call `base_url` in-process and only *code* ever runs in a
    sandbox. The bridge exists for the future case where a consumer inside a Quome sandbox needs the model
    (sandbox RAM is too small to host it): it fronts local Ollama with auth so the model is never exposed
    raw. Auth prefers OIDC (short-lived EdDSA tokens audienced to the bridge); a static shared
    token is the fallback when `oidc_issuer` is unset. With neither configured the bridge fails closed.

    `weights_path` names the weight file the self-hosted model was loaded from; when set, the MBOM carries the
    SHA-256 of those bytes (VSLA-F-3). When unset the MBOM says `weights: {unmeasured: true}`; it never hashes the
    model's name. `reviewer_provider`/`reviewer_model` select a reviewer on a different model family from the
    patcher (VSLA-P-10); unset, the reviewer runs on the pipeline provider and `distinctFamily` is false."""

    base_url: str = "http://localhost:11434/v1"          # local Ollama, OpenAI-compatible; consumed in-process
    model: str = "qwen3.8:27b"
    api_key_env: str = "QUDISCLOSE_INFERENCE_KEY"        # OpenAI-client key for the local consumer (Ollama ignores)
    weights_path: str | None = None                      # path of the loaded weight file; hashed into the MBOM when set
    reviewer_provider: str | None = None                 # anthropic | local | claude | scripted; None = same provider as the pipeline
    reviewer_model: str | None = None                    # model for the reviewer role (family must differ from the patcher's)
    reviewer_base_url: str | None = None                 # for reviewer_provider=local: endpoint (default: base_url)
    # bridge (remote consumers reach local Ollama through this + a tunnel)
    bridge_host: str = "127.0.0.1"
    bridge_port: int = 8900
    public_url: str | None = None                        # tunnel URL fronting the bridge, e.g. an ngrok https URL
    # bridge auth — OIDC-issued tokens (preferred) …
    oidc_issuer: str | None = None                     # OIDC issuer; discovery yields jwks_uri
    oidc_audience: str = "qudisclose-inference"        # tokens must carry this aud
    # … or a static shared secret (only when oidc_issuer is unset)
    static_token_env: str = "QUDISCLOSE_INFERENCE_TOKEN"


class VSLAConfig(BaseModel):
    """VSLA (Vulnerability-disclosure Supply-chain Levels for Agents): qudisclose attests every case it verifies and
    verifies attestations reporters submit. Spec: https://github.com/AAI-Society/vsla (v1.0, revision 4)."""

    enabled: bool = True
    operator: str = ""                                    # accountable organisation; defaults to the intake host
    finder_identity: str = ""                             # name of this deployment's finder key; defaults to qudisclose@<host>
    authorization_basis: str = "ownership"                # ownership | program | engagement | safe-harbour (VSLA-F-19)
    authorization_ref: str | None = None                  # program scope URL, engagement id or policy URL
    # the L2 floor (spec: trust-rubric.md, v1.1)
    floor: float = 0.6                                    # trust-rubric floor for Identity L2
    min_entries: int = 5                                  # counted countersigned ledger entries needed for L2
    min_countersigners: int = 2                           # distinct pinned countersigners needed for L2
    min_age_days: float = 30                              # hard age gate: the oldest counted entry is at least this old
    require_leaves: bool = False                          # refuse statements that do not carry transcript leaves
    # keys this platform pins (VSLA-V-1, VSLA-V-5): keyid -> "ed25519:<hex>" | {"public", "validFrom"?, "revokedAt"?}
    pinned_countersigners: dict[str, Any] = Field(default_factory=dict, description="platform:<name> / maintainer:<name> keys counted toward m")
    trusted_roots: dict[str, Any] = Field(default_factory=dict, description="environment root-of-trust name -> key")
    trusted_providers: dict[str, Any] = Field(default_factory=dict, description="weight-attestation provider name -> key")
    trusted_operators: dict[str, Any] = Field(default_factory=dict, description="operator name -> key (revoke entries)")
    expectations_path: str | None = None                  # extra expectations json {harness: {name: {version: sha256}}, measurements: [...]} (VSLA-V-6)
    environment_evidence_path: str | None = None          # reference signed-quote evidence file (vsla/environment.py); None = L3 not claimed
    # admission control for re-execution (VSLA-P-12)
    reexec_per_identity_per_hour: int = 20                # re-executions one finder identity may trigger per hour
    reexec_concurrent: int = 2                            # concurrent re-execution sandboxes
    reexec_unknown_identities: bool = False               # re-execute for an identity that presents no ledger entry verifiable under a pinned countersigner (else defer to the slow lane with a not-attempted receipt)
    # what this verifier demands of receipts and re-executions it accepts from others (VSLA-P-16, VSLA-P-11)
    require_anchor: bool = False                          # I3 and E7 require a verified log-inclusion anchor (a third-party verifier should set this)
    accept_timestamp_anchor: bool = False                 # let the signed-timestamp form (a pinned log key's timestamp, not log inclusion) satisfy require_anchor
    require_isolation: str | None = None                  # "vm" | "container": E7 accepts re-executions only in at least this isolation class
    trusted_logs: dict[str, Any] = Field(default_factory=dict, description="transparency-log name -> key (receipt anchors, VSLA-P-16)")
    # identity
    allow_ephemeral_platform_key: bool = False            # demos/tests only: run with a freshly generated platform key


class Config(BaseModel):
    server_name: str = "qudisclose"
    public_url: str = "http://127.0.0.1:8765/mcp"
    host: str = "127.0.0.1"
    port: int = 8765
    db_dsn: str = "postgresql:///qudisclose"
    keys_dir: str = "keys"
    out_dir: str = "out"
    repos: dict[str, RepoConfig] = Field(default_factory=dict)
    policy: Policy = Field(default_factory=Policy)
    hunter: HunterConfig = Field(default_factory=HunterConfig)
    sandbox: SandboxConfig = Field(default_factory=SandboxConfig)
    inference: InferenceConfig = Field(default_factory=InferenceConfig)
    vsla: VSLAConfig = Field(default_factory=VSLAConfig)
    model: str = "claude-opus-5-5"
    provider: str = Field(default="anthropic", description="anthropic | local (self-hosted OpenAI-compatible, uses `inference`) | scripted")
    github_token_env: str = "QUDISCLOSE_GITHUB_TOKEN"
    webhook_secrets: dict[str, str] = Field(default_factory=dict, description="sender -> HMAC secret (prefer env refs: $VAR)")
    trusted_reporters: dict[str, str] = Field(default_factory=dict, description="reporter identity -> Ed25519 public key hex")
    rate_limit_per_minute: int = 60

    @classmethod
    def load(cls, path: str | Path | None = None) -> Config:
        p = Path(path or os.environ.get("QUDISCLOSE_CONFIG", "qudisclose.json"))
        if not p.exists():
            return cls()
        cfg = cls.model_validate(json.loads(p.read_text()))
        cfg.webhook_secrets = {k: (os.environ.get(v[1:], "") if v.startswith("$") else v) for k, v in cfg.webhook_secrets.items()}
        return cfg

    def save(self, path: str | Path = "qudisclose.json") -> None:
        Path(path).write_text(self.model_dump_json(indent=2))
