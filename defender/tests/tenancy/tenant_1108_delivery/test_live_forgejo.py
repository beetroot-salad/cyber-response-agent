from __future__ import annotations

from defender.tests.support.shared._fixture_uuid import fixture_uuid

import base64
import json
import os
import time
import uuid
from pathlib import Path

import httpx
import pytest

from defender import _git
from defender.learning.author.version_control.auth import ForgejoIdentity
from defender.learning.author.version_control.forgejo import ForgeAddress, ForgejoForge
from defender.learning.author.version_control.transport import GitTransport

pytestmark = pytest.mark.live


def test_real_forgejo_accepts_scoped_short_lived_jwt(tmp_path):
    location = os.environ.get("FORGEJO_TEST_CONFIG")
    if not location:
        pytest.skip("set FORGEJO_TEST_CONFIG for the disposable Forgejo integration")
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding

    config = json.loads(Path(location).read_text())
    key = serialization.load_pem_private_key(
        Path(config["key_file"]).read_bytes(), None
    )

    def jwt(**extra):
        now = int(time.time())
        claims = dict(
            iss=config["issuer"],
            aud=config["audience"],
            sub="fixture",
            tenant_id=fixture_uuid("tenant:blue"),
            iat=now,
            exp=now + 600,
        )
        claims.update(extra)

        def encode(value):
            return base64.urlsafe_b64encode(value).decode().rstrip("=")

        signed = (
            encode(json.dumps({"alg": "RS256", "kid": "fixture"}).encode())
            + "."
            + encode(json.dumps(claims).encode())
        )
        return (
            signed
            + "."
            + encode(key.sign(signed.encode(), padding.PKCS1v15(), hashes.SHA256()))
        )

    value = jwt()
    with (
        httpx.Client(
            transport=httpx.MockTransport(
                lambda request: httpx.Response(200, json={"data": {"token": value}})
            )
        ) as vault,
        httpx.Client(timeout=30) as client,
    ):
        identity = ForgejoIdentity(
            fixture_uuid("tenant:blue"), config["issuer"], "tenant-blue", config["audience"], vault
        )
        address = ForgeAddress.parse(config["origin"])
        forge = ForgejoForge(origin=config["origin"], identity=identity, client=client)
        assert isinstance(forge.repository_id(), int)
        forge.verify_main_protection()
        _git.git(["init", "-b", "main"], cwd=tmp_path)
        _git.git(["remote", "add", "origin", config["origin"]], cwd=tmp_path)

        transport = GitTransport(tmp_path, config["origin"], identity, 30)
        transport.fetch()
        _git.git(["reset", "--hard", "origin/main"], cwd=tmp_path)
        _git.git(
            [
                "-c",
                "user.name=Fixture",
                "-c",
                "user.email=fixture@invalid",
                "commit",
                "--allow-empty",
                "-m",
                "JWT integration",
            ],
            cwd=tmp_path,
        )
        branch = "lessons/jwt-" + uuid.uuid4().hex
        commit = _git.git(["rev-parse", "HEAD"], cwd=tmp_path)  # lint-oracle: ok — identify the fixture commit passed to transport; not an expected-value oracle
        transport.push(commit, branch)
        assert forge.open_pr(
            base="main", head=branch, title="JWT fixture", body="Fixture"
        )
        with pytest.raises(_git.GitError):
            transport.push(commit, "main")
        for rejected in [
            jwt(exp=int(time.time()) - 60),
            jwt(tenant_id=fixture_uuid("tenant:other")),
            jwt(aud="wrong-audience"),
            value[:-10] + "invalidsig",
        ]:
            response = client.get(
                address.api, headers={"Authorization": "Bearer " + rejected}
            )
            assert response.status_code == 401
        other = ForgeAddress.parse(config["other_origin"])
        response = client.get(other.api, headers={"Authorization": "Bearer " + value})
        assert response.status_code in {403, 404}
        with pytest.raises(_git.GitError):
            GitTransport(tmp_path, config["other_origin"], identity, 30).fetch()
