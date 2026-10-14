from __future__ import annotations

import importlib
import json
import os
import subprocess
from pathlib import Path

import httpx
import pytest

from defender.tests import _tenants1106 as tenants

ORIGIN = "http://forge.invalid:3000/tenants/blue.git"
TOKEN = "p3-blue-secret-credential"
DEFENDER = Path(__file__).resolve().parents[2]


def target():
    # Lazy import: the contract must collect before its implementation exists.
    return importlib.import_module("defender.learning.author.tenant_delivery")


def git(cwd, *args):
    # lint-raw-git: test-only real repository fixture and observation boundary.
    proc = subprocess.run(["git", *map(str, args)], cwd=cwd, text=True,
                          capture_output=True, check=True,
                          env={**os.environ, "GIT_CONFIG_NOSYSTEM": "1",
                               "GIT_AUTHOR_NAME": "P3", "GIT_AUTHOR_EMAIL": "p3@test.invalid",
                               "GIT_COMMITTER_NAME": "P3", "GIT_COMMITTER_EMAIL": "p3@test.invalid"})
    return proc.stdout.strip()


class ForgeHTTP:
    """Boundary fake: replies from the observed Forgejo schema, records actual requests."""
    def __init__(self):
        self.requests = []
        self.protection = {"name": "main", "protected": True, "user_can_push": False}
        self.pages = {1: []}
        self.fail_create = False
        self.client = httpx.Client(transport=httpx.MockTransport(self.reply))

    def reply(self, request):
        self.requests.append(request)
        path = request.url.path
        if path.endswith("/branches/main"):
            return httpx.Response(200, content=json.dumps(self.protection),
                                  headers={"Content-Type": "application/json"})
        if path.endswith("/pulls") and request.method == "GET":
            page = int(request.url.params.get("page", "1"))
            headers = {"Link": f'<{request.url.copy_set_param("page", page + 1)}>; rel="next"'} if page + 1 in self.pages else {}
            return httpx.Response(200, json=self.pages.get(page, []), headers=headers)
        if path.endswith("/pulls") and request.method == "POST":
            return httpx.Response(503 if self.fail_create else 201,
                                 json={"html_url": "http://forge.invalid:3000/tenants/blue/pulls/7"})
        raise AssertionError(f"unexpected HTTP boundary: {request.method} {request.url}")

    @property
    def creates(self):
        return [json.loads(r.content) for r in self.requests if r.method == "POST"]


@pytest.fixture
def repo(tmp_path):
    root = tmp_path / "data"
    tenants.place_tenant(root, "blue")
    tenant = tenants.accept(root, "blue")
    clone = tenant.knowledge
    (tenant.agent / "lessons").mkdir()
    (tenant.agent / "lessons" / "seed.md").write_text("seed\n")
    git(clone, "init", "-b", "main")
    git(clone, "config", "user.name", "P3")
    git(clone, "config", "user.email", "p3@test.invalid")
    git(clone, "add", ".")
    git(clone, "commit", "-m", "seed")
    remote = tmp_path / "origin.git"
    git(tmp_path, "clone", "--bare", clone, remote)
    git(clone, "remote", "add", "origin", ORIGIN)
    # Git performs real local transport; delivery still validates the actual network origin.
    git(clone, "config", f"url.{remote}.insteadOf", ORIGIN)
    git(clone, "fetch", "origin")
    credentials = tenant.dir / "forge" / "git-credentials"
    credentials.parent.mkdir()
    credentials.write_text(f"http://bot:{TOKEN}@forge.invalid:3000\n")
    credentials.chmod(0o600)
    return tenant, remote, credentials


def delivery(repo, http):
    return target().TenantDelivery.open(repo[0], defender_dir=DEFENDER, client=http.client)


def advance_remote(repo, tmp_path):
    writer = tmp_path / "merger"
    git(tmp_path, "clone", repo[1], writer)
    (writer / "agent" / "lessons" / "merged.md").write_text("human-reviewed merge\n")
    git(writer, "add", ".")
    git(writer, "commit", "-m", "human merge")
    git(writer, "push", "origin", "main")
    return git(writer, "rev-parse", "HEAD")
