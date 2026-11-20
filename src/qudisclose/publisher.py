"""Where a verified fix goes. `LocalPublisher` writes everything to an output directory (offline / demo);
`GitHubPublisher` stages the fix privately beside a draft repository security advisory, using short-lived brokered
leases, and leaves disclosure to the maintainer."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

import httpx2

from qudisclose.models import PatchResult, ReleasePlan, Report
from qudisclose.security.broker import CredentialBroker


@dataclass
class PublishResult:
    pr_url: str
    advisory_url: str
    published: bool


class Publisher(Protocol):
    def publish(self, report: Report, plan: ReleasePlan, patch: PatchResult, *, holder: str,
                attestations: dict[str, Any] | None = None) -> PublishResult: ...


class LocalPublisher:
    def __init__(self, out_dir: str | Path) -> None:
        self.out = Path(out_dir)

    def publish(self, report: Report, plan: ReleasePlan, patch: PatchResult, *, holder: str,
                attestations: dict[str, Any] | None = None) -> PublishResult:
        d = self.out / report.id
        d.mkdir(parents=True, exist_ok=True)
        for kind, body in (attestations or {}).items():          # vsla.finding.json, vsla.patch.json, vsla.receipt.json
            (d / f"vsla.{kind}.json").write_text(json.dumps(body, indent=2))
        (d / "fix.patch").write_text(patch.proposal.diff)
        (d / "PR.md").write_text(f"# {plan.pr_title}\n\n{plan.pr_body}\n\n## Changelog\n\n{plan.changelog_entry}\n")
        (d / "advisory.osv.json").write_text(json.dumps(_osv(plan), indent=2))
        (d / "cve-request.txt").write_text(plan.advisory.cve_request)
        return PublishResult(pr_url=str(d / "PR.md"), advisory_url=str(d / "advisory.osv.json"), published=True)


class GitHubPublisher:
    """Creates a draft repository security advisory, the advisory's temporary private fork, and a branch + PR inside that
    fork. Nothing about the bug reaches the public repository: an ordinary PR there would disclose it to everyone before
    any user could upgrade. The maintainer merges in the advisory and publishes it on GitHub, then runs `disclose`.
    Each step uses its own lease."""

    def __init__(self, broker: CredentialBroker, api: str = "https://api.github.com") -> None:
        self.broker, self.api = broker, api

    def _client(self, token: str) -> httpx2.Client:
        return httpx2.Client(base_url=self.api, timeout=30, headers={
            "Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"})

    def publish(self, report: Report, plan: ReleasePlan, patch: PatchResult, *, holder: str,
                attestations: dict[str, Any] | None = None, files: dict[str, str | None] | None = None,
                base_revision: str | None = None) -> PublishResult:
        """`files` are the verified contents of every path the diff touches (None = deleted) and `base_revision` the
        commit they were verified against; the PR branch starts there so it carries exactly the verified change."""
        repo = report.submission.repo
        if not files or not base_revision:
            raise ValueError("GitHubPublisher needs the verified files and the revision they were verified against")
        if attestations:
            from qudisclose.vsla.dsse import envelope_payload, statement_digest
            lines = []
            for kind in ("finding", "patch"):
                env = attestations.get(kind)
                if env:
                    lvl = envelope_payload(env)["predicate"].get("claimedLevel")
                    lines.append(f"- VSLA {kind} statement: claimed L{lvl}, sha256 `{statement_digest(env)}`")
            if lines:
                plan = plan.model_copy(update={"pr_body": plan.pr_body + "\n\n### VSLA attestation\n" + "\n".join(lines)
                                               + "\n\nVerify with `qudisclose verify-attestation` (spec: https://github.com/AAI-Society/vsla)."})
        adv_lease = self.broker.lease(purpose="advisory:publish", repo=repo, holder=holder)
        try:
            ghsa, adv_url = self._create_advisory(repo, plan, adv_lease.reveal())
            fork = self._private_fork(repo, ghsa, adv_lease.reveal())
        finally:
            self.broker.revoke(adv_lease.lease_id)
        pr_lease = self.broker.lease(purpose="pr:create", repo=repo, holder=holder)
        try:
            pr_url = self._open_pr(fork, plan, files, base_revision, pr_lease.reveal())
        finally:
            self.broker.revoke(pr_lease.lease_id)
        return PublishResult(pr_url=pr_url, advisory_url=adv_url, published=False)

    def _private_fork(self, repo: str, ghsa: str, token: str) -> str:
        """The draft advisory's temporary private fork; returns its `owner/name`."""
        with self._client(token) as c:
            r = c.post(f"/repos/{repo}/security-advisories/{ghsa}/forks")
            r.raise_for_status()
            return str(r.json()["full_name"])

    def _open_pr(self, repo: str, plan: ReleasePlan, files: dict[str, str | None], base_revision: str, token: str) -> str:
        """Branches from the verified base, writes the verified files through the contents API (no local git credential
        ever exists) and opens the PR inside `repo`, the private fork. Merging it into the fork's default branch is a
        3-way merge, so changes made since the base are kept, and a conflict shows up as a conflict."""
        with self._client(token) as c:
            base = c.get(f"/repos/{repo}").json()["default_branch"]
            branch = f"qudisclose/fix-{plan.advisory.id.lower()}"
            c.post(f"/repos/{repo}/git/refs", json={"ref": f"refs/heads/{branch}", "sha": base_revision}).raise_for_status()
            for path, content in files.items():
                existing = c.get(f"/repos/{repo}/contents/{path}", params={"ref": branch})
                if content is None:
                    if existing.status_code == 200:
                        c.request("DELETE", f"/repos/{repo}/contents/{path}", json={"message": f"security: {plan.pr_title}",
                                  "sha": existing.json()["sha"], "branch": branch}).raise_for_status()
                    continue
                body: dict[str, Any] = {"message": f"security: {plan.pr_title}", "content": _b64(content), "branch": branch}
                if existing.status_code == 200:
                    body["sha"] = existing.json()["sha"]
                c.put(f"/repos/{repo}/contents/{path}", json=body).raise_for_status()
            pr = c.post(f"/repos/{repo}/pulls", json={"title": plan.pr_title, "body": plan.pr_body, "head": branch, "base": base})
            pr.raise_for_status()
            return pr.json()["html_url"]

    def _create_advisory(self, repo: str, plan: ReleasePlan, token: str) -> tuple[str, str]:
        """A draft repository advisory (the REST API creates advisories as drafts); returns (GHSA id, URL)."""
        a = plan.advisory
        with self._client(token) as c:
            r = c.post(f"/repos/{repo}/security-advisories", json={
                "summary": a.summary[:1024], "description": a.details[:65535], "severity": a.severity if a.severity != "none" else "low",
                "cvss_vector_string": a.cvss_vector, "cwe_ids": [a.cwe],
                "vulnerabilities": [{"package": {"name": x.get("package", {}).get("name"), "ecosystem": x.get("package", {}).get("ecosystem")},
                                      "vulnerable_version_range": x.get("vulnerable_version_range"), "patched_versions": plan.new_version} for x in a.affected] or
                                   [{"package": {"name": repo.split("/")[1], "ecosystem": "other"}, "patched_versions": plan.new_version}],
                "credits": [{"login": cr.removeprefix("github:"), "type": "reporter"} for cr in a.credits if cr.startswith("github:")],
            })
            r.raise_for_status()
            return str(r.json()["ghsa_id"]), str(r.json()["html_url"])


def _osv(plan: ReleasePlan) -> dict[str, Any]:
    a = plan.advisory
    return {"schema_version": "1.6.0", "id": a.id, "summary": a.summary, "details": a.details,
            "severity": [{"type": "CVSS_V4", "score": a.cvss_vector}], "affected": a.affected,
            "references": [{"type": "WEB", "url": u} for u in a.references],
            "database_specific": {"cwe_ids": [a.cwe], "severity": a.severity.upper()},
            "credits": [{"name": c, "type": "REPORTER"} for c in a.credits]}


def _b64(s: str) -> str:
    import base64
    return base64.b64encode(s.encode()).decode()

