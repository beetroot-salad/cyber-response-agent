"""The gate that holds #1440's "every Forgejo call, and every OpenBao call of the lifecycle, is named
in its adapter": lint_inline_api_paths."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from _by_path import load_lint_gate

_GATE = load_lint_gate("lint_inline_api_paths")


def _pyfile(tree: Path, rel: str, src: str) -> Path:
    p = tree / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(src, encoding="utf-8")
    return p


def _baseline(path: Path, fingerprints: tuple[str, ...] = ()) -> Path:
    path.write_text(json.dumps({"//": "test", "entries": {fp: "" for fp in fingerprints}}), encoding="utf-8")
    return path


def _fingerprints(tree: Path) -> list[str]:
    return sorted(f.fingerprint for f in _GATE._scan(tree))


# The shapes the three callers had before #1440, verbatim.
@pytest.mark.parametrize(("rel", "src", "fingerprint"), [
    ("lifecycle/_service.py",
     "async def _bot(self, gen):\n    await self._forge.delete(f\"/api/v1/admin/users/{gen.bot_login}\")\n",
     "lifecycle/_service.py:_bot:forgejo"),
    ("lifecycle/_host.py",
     "async def _install(self, repo, bearer):\n    await self._forge.get(f\"/api/v1/repos/{repo}\", headers=bearer)\n",
     "lifecycle/_host.py:_install:forgejo"),
    ("learning/author/version_control/forgejo.py",
     "class A:\n    @property\n    def api(self):\n        return f\"{self.origin}/api/v1/repos/{self.owner}/{self.repo}\"\n",
     "learning/author/version_control/forgejo.py:api:forgejo"),
    ("lifecycle/_service.py",
     "async def _accessor(self):\n    return await self._bao.get(\"/v1/sys/auth\")\n",
     "lifecycle/_service.py:_accessor:openbao"),
    ("lifecycle/_bot.py", "LOGIN = \"/v1/auth/approle/login\"\n", "lifecycle/_bot.py:<module>:openbao"),
], ids=["forge-admin", "forge-bearer", "learning-api-root", "openbao-call", "openbao-constant"])
def test_an_inline_path_is_flagged(tmp_path, rel, src, fingerprint):
    _pyfile(tmp_path, rel, src)

    assert _fingerprints(tmp_path) == [fingerprint]
    assert _GATE.main([], scope=tmp_path, baseline_path=_baseline(tmp_path / "b.json")) == 1


def test_the_adapters_and_their_callers_are_clean(tmp_path):
    """The adapter writes the paths; a caller sends what it answers. An OpenBao path outside the
    lifecycle (the credential proxy's own) and a docstring naming a path are not this rule's."""
    _pyfile(tmp_path, "_forgejo_api.py", "_API = \"/api/v1\"\n\ndef user(login):\n    return f\"{_API}/users/{login}\"\n")
    _pyfile(tmp_path, "_openbao_api.py", "def auth_mounts():\n    return \"/v1/sys/auth\"\n")
    _pyfile(tmp_path, "lifecycle/_service.py", (
        "\"\"\"Reads `GET /api/v1/users/<login>` and `/v1/sys/auth`.\"\"\"\n"
        "from defender import _forgejo_api as forgejo, _openbao_api as openbao\n\n"
        "async def _bot(self, login):\n"
        "    \"\"\"Calls /api/v1/users/{login}.\"\"\"\n"
        "    call = forgejo.user(login)\n"
        "    await self._forge.request(call.method, call.path, **call.options())\n"
        "    await self._bao.request(openbao.auth_mounts().method, openbao.auth_mounts().path)\n"))
    _pyfile(tmp_path, "credential_proxy/_openbao.py", "def url(addr, rest):\n    return f\"{addr}/v1/{rest}\"\n")

    assert _fingerprints(tmp_path) == []
    assert _GATE.main([], scope=tmp_path, baseline_path=_baseline(tmp_path / "b.json")) == 0


def test_a_second_adapter_elsewhere_is_not_the_adapter(tmp_path):
    """By path, not basename: a second `_forgejo_api.py` below the root is a caller like any other."""
    _pyfile(tmp_path, "learning/_forgejo_api.py", "def user(login):\n    return f\"/api/v1/users/{login}\"\n")

    assert _fingerprints(tmp_path) == ["learning/_forgejo_api.py:user:forgejo"]


def test_tests_are_excluded_and_a_marked_site_is_suppressed(tmp_path):
    _pyfile(tmp_path, "tests/test_x.py", "def f():\n    return \"/api/v1/users/x\"\n")
    _pyfile(tmp_path, "lifecycle/_x.py", (
        "def f(o):\n    return f\"{o}/api/v1/version\"  # lint-api-path: ok — a probe of the forge itself\n"))

    assert _fingerprints(tmp_path) == []
