"""The forge and the repository for #1471's adoption tests: `ForgeHTTP` answering as the live Forgejo probes G-A11..G-A14 saw
it, over a real bare remote. Fakes record and inject; every outcome is the code under test's."""
from __future__ import annotations


import httpx

from defender.tests.tenancy.tenant_1108_delivery._support import (
    ForgeHTTP,
    _pulls_updating,
    _remote_tip,
    _save_pulls,
    forge_pulls,
    git,
    git_bytes,
    pr_row,
)

SYSTEM = "elastic"
DIGEST = "0123456789abcdef" * 4
OTHER_DIGEST = "fedcba9876543210" * 4
RENDERING = {
    f"agent/skills/{SYSTEM}/SKILL.md": b"---\nname: defender-elastic\ndescription: x\n---\n# Visibility\r\n$Id$\n",
    f"agent/skills/{SYSTEM}/execution.md": b"# Execution\nCall `list_verbs`.\n",
    f"agent/skills/gather/queries/{SYSTEM}/by-host.md": b"---\nid: elastic.by-host\nverb: x\n---\n\xff\xfe raw bytes\n",
}


def branch_for(digest: str, system: str = SYSTEM) -> str:
    """The branch P-9 names (restated from the design's literal rule, never from the code under test)."""
    return f"adopt/{system}/{digest[:16]}"


class AdoptionForge(ForgeHTTP):
    """`ForgeHTTP` as Forgejo 17 answered the probes: `head.label` is the bare branch name and survives a branch delete while
    `head.ref` becomes `refs/pull/N/head` (G-A11); a create on a head with an open PR is 409 (G-A12), on a closed one 201 (G-A13),
    on a missing branch 404 (G-A14)."""

    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self.after_listing = None

    # -- the probes' answers ---------------------------------------------------------------------------------------
    def _create(self, body):
        if self.fail_create:
            return httpx.Response(503, json={"message": "the forge failed"})
        sha = _remote_tip(self.remote, body["head"])
        if sha is None:
            return httpx.Response(404, json={"message": "The target couldn't be found."})
        if any(r["state"] == "open" and r["head"]["label"] == body["head"] for r in self.prs):
            return httpx.Response(409, json={"message": "pull request already exists for these targets"})
        number = max([6, *(row["number"] for row in self.prs)]) + 1
        row = self._row(number, body["head"], sha=sha)
        row["user"] = {"login": self.login}
        row["body"] = body.get("body", "")
        return httpx.Response(201, json=self.add_pr(row))

    @staticmethod
    def _row(number, branch, *, sha=None, state="open", merged=False, deleted=False):
        row = pr_row(number, branch, sha=sha, state=state, merged=merged)
        row["head"]["label"] = branch
        if deleted:
            row["head"]["ref"] = f"refs/pull/{number}/head"
        return row

    # -- what a racer or a person does on the forge ----------------------------------------------------------------------
    def plant(self, branch, *, state="open", deleted=False):
        """A PR on `branch` as the listing shows it: `open`, `merged` or `closed` (unmerged), its branch deleted or not. Returns its number."""
        number = max([6, *(row["number"] for row in self.prs)]) + 1
        sha = _remote_tip(self.remote, branch)
        self.add_pr(self._row(number, branch, sha=sha, state="open" if state == "open" else "closed",
                              merged=state == "merged", deleted=deleted))
        return number

    def settle(self, number, *, merged, delete_branch=False):
        """A person merging or closing PR `number`, the branch deleted or not."""
        with _pulls_updating(self.remote):
            rows = forge_pulls(self.remote)
            [row] = [r for r in rows if r["number"] == number]
            branch = row["head"]["ref"]
            row.update(state="closed", merged=merged, merged_at="2026-10-16T00:00:00Z" if merged else None)
            if delete_branch:
                row["head"]["ref"] = f"refs/pull/{number}/head"
            _save_pulls(self.remote, rows)
        if delete_branch:
            git(self.remote, "update-ref", "-d", f"refs/heads/{branch}")

    def reply(self, request):
        response = super().reply(request)
        if (self.after_listing is not None and request.method == "GET" and request.url.path.endswith("/pulls")
                and int(request.url.params.get("page") or 1) * min(int(request.url.params.get("limit") or 50), self.page_size)
                >= int(response.headers.get("X-Total-Count", 0))):
            racer, self.after_listing = self.after_listing, None
            racer()
        return response

    # -- observations ----------------------------------------------------------------------------------------------------
    def requests_by(self, method):
        return [(r.url.path.rsplit("/api/v1/repos/tenants/blue", 1)[-1], r) for r in self.requests if r.method == method]

    def creates_of(self, branch):
        return [c for c in self.creates if c["head"] == branch]


def racer_push(remote, tmp_path, branch, files, *, message="a racer's commit", name="racer"):
    """Another process landing `files` ({path: bytes}) on `branch` of the remote as a commit off `main`, the way a racing job would."""
    clone = tmp_path / name
    git(tmp_path, "clone", remote, clone)
    git(clone, "checkout", "-b", branch, "origin/main")
    for path, data in files.items():
        (clone / path).parent.mkdir(parents=True, exist_ok=True)
        (clone / path).write_bytes(data)
    git(clone, "add", "-A")
    git(clone, "commit", "-m", message)
    git(clone, "push", "origin", branch)
    return git(clone, "rev-parse", "HEAD")


def tree_diff(remote, base, tip):
    """`(mode, path)` of every entry that differs between two commits of `remote`, with its status: `[(status, mode, path)]`."""
    out = git(remote, "diff-tree", "-r", "--no-renames", "--raw", base, tip)
    rows = [line.split(None, 5) for line in out.splitlines() if line.startswith(":")]
    return sorted((r[4], r[1], r[5]) for r in rows)


def blobs_at(remote, rev, paths):
    return {p: git_bytes(remote, "cat-file", "blob", f"{rev}:{p}") for p in paths}


def commits_between(remote, base, tip):
    return git(remote, "rev-list", f"{base}..{tip}").split()


def main_tip(remote):
    return git(remote, "rev-parse", "refs/heads/main")
