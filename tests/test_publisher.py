import json

import httpx2

from qudisclose.models import Status
from qudisclose.publisher import GitHubPublisher
from qudisclose.security import CredentialBroker
from tests.conftest import new_report

UPSTREAM, FORK, GHSA = "example/vulnpkg", "example/vulnpkg-ghsa-abcd-efgh-ijkl", "GHSA-abcd-efgh-ijkl"


class FakeGitHub:
    """Records every request and answers the handful of REST calls the publisher makes."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []

    def handler(self, req: httpx2.Request) -> httpx2.Response:
        m, p = req.method, req.url.path
        self.calls.append((m, p))
        if m == "GET" and p.startswith("/repos/") and p.count("/") == 3:
            return httpx2.Response(200, json={"default_branch": "main", "full_name": p[len("/repos/"):]})
        if m == "GET" and "/git/ref/heads/" in p:
            return httpx2.Response(200, json={"object": {"sha": "0" * 40}})
        if m == "POST" and p.endswith("/git/refs"):
            return httpx2.Response(201, json={})
        if m == "GET" and "/contents/" in p:
            return httpx2.Response(404, json={})
        if m == "PUT" and "/contents/" in p:
            return httpx2.Response(201, json={})
        if m == "POST" and p.endswith("/pulls"):
            return httpx2.Response(201, json={"html_url": f"https://github.com{p[len('/repos'):-len('/pulls')]}/pull/1"})
        if m == "POST" and p == f"/repos/{UPSTREAM}/security-advisories":
            return httpx2.Response(201, json={"ghsa_id": GHSA, "html_url": f"https://github.com/{UPSTREAM}/security/advisories/{GHSA}"})
        if m == "POST" and p == f"/repos/{UPSTREAM}/security-advisories/{GHSA}/forks":
            return httpx2.Response(202, json={"full_name": FORK, "default_branch": "main"})
        return httpx2.Response(404, json={"message": f"unexpected {m} {p}"})

    def writes_to(self, repo: str) -> list[tuple[str, str]]:
        return [(m, p) for m, p in self.calls if m in ("POST", "PUT", "PATCH") and p.startswith(f"/repos/{repo}/")]


def _github_publisher(fake: FakeGitHub) -> GitHubPublisher:
    pub = GitHubPublisher(CredentialBroker(fetch=lambda purpose, repo: "tok"))
    pub._client = lambda token: httpx2.Client(base_url=pub.api, transport=httpx2.MockTransport(fake.handler))  # type: ignore[method-assign]
    return pub


def test_github_publisher_keeps_the_fix_out_of_the_public_repository(env):
    """An unmerged PR on a public repository discloses the bug to everyone before any user can upgrade. The fix goes to
    the draft advisory's temporary private fork; nothing is written to the public repository except the draft advisory."""
    cfg, store, audit, provider, orch = env
    fake = FakeGitHub()
    orch.publisher = _github_publisher(fake)
    rep, _ = orch.intake(new_report(), actor="x")
    r = orch.run_case(rep.id)
    assert r.status == Status.CLOSED, [e.kind for e in store.events(rep.id)]
    assert fake.writes_to(UPSTREAM) == [("POST", f"/repos/{UPSTREAM}/security-advisories"),
                                        ("POST", f"/repos/{UPSTREAM}/security-advisories/{GHSA}/forks")], fake.calls
    assert ("POST", f"/repos/{FORK}/pulls") in fake.calls and ("POST", f"/repos/{FORK}/git/refs") in fake.calls
    # the case stays embargoed: the fix is staged privately and the advisory is a draft
    r = store.get_report(rep.id)
    assert r.classification == "embargoed"
    published = next(e for e in store.events(rep.id) if e.kind == "published")
    assert published.data["disclosed"] is False and FORK in published.data["pr_url"]
    assert any(e.kind == "awaiting_disclosure" for e in store.events(rep.id))


def test_disclose_makes_a_staged_case_public(env):
    """After the maintainer merges the private fork and publishes the advisory on GitHub, `disclose` lifts the embargo."""
    cfg, store, audit, provider, orch = env
    orch.publisher = _github_publisher(FakeGitHub())
    rep, _ = orch.intake(new_report(), actor="x")
    orch.run_case(rep.id)
    assert store.get_report(rep.id).classification == "embargoed"
    r = orch.disclose(rep.id, "maintainer")
    assert r.classification == "public" and store.get_report(rep.id).classification == "public"
    assert any(e.kind == "disclosed" for e in store.events(rep.id))
    assert json.dumps([e.kind for e in store.events(rep.id)]).count("disclosed") == 1
    ok, msg = audit.verify_chain()
    assert ok, msg


def test_github_pr_carries_the_verified_change_on_the_verified_base(env):
    """The PR must contain the verified diff, applied to the revision it was verified against. Writing whole files onto
    the current branch tip would silently revert anything merged since; losing the files would open an empty PR."""
    cfg, store, audit, provider, orch = env
    fake = FakeGitHub()
    bodies: list[tuple[str, dict]] = []
    inner = fake.handler

    def handler(req: httpx2.Request) -> httpx2.Response:
        if req.method in ("POST", "PUT", "DELETE") and req.content:
            bodies.append((req.url.path, json.loads(req.content)))
        return inner(req)

    pub = GitHubPublisher(CredentialBroker(fetch=lambda purpose, repo: "tok"))
    pub._client = lambda token: httpx2.Client(base_url=pub.api, transport=httpx2.MockTransport(handler))  # type: ignore[method-assign]
    orch.publisher = pub
    rep, _ = orch.intake(new_report(), actor="x")
    orch.run_case(rep.id)
    revision = store.get_artifact(rep.id, "subject_revision")["sha"]
    ref = next(b for p, b in bodies if p.endswith("/git/refs"))
    assert ref["sha"] == revision                       # branched from the verified base, not today's tip
    puts = {p.rsplit("/contents/", 1)[1] for p, b in bodies if "/contents/" in p}
    assert puts == {"vulnpkg/files.py"}, puts            # the verified change is in the PR
    import base64
    content = base64.b64decode(next(b for p, b in bodies if p.endswith("/contents/vulnpkg/files.py"))["content"]).decode()
    assert "is_relative_to" in content
