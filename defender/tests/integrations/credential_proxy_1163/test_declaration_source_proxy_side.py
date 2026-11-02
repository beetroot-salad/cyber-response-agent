"""#1163 repair (proxy side): a merged declaration is read strictly: a repeated key anywhere in the
file, or a key nobody reads, makes the system unusable rather than half-applied."""
from __future__ import annotations

import pytest

from defender.tests.integrations.credential_proxy_1163 import _tenant as T
from defender.tests.integrations.credential_proxy_1163._target import ACCESS_FILE

ACCESS = ACCESS_FILE.format(system="identity")


def _yaml(base: str, *, auth: str = "{scheme: bearer, field: api_key}",
          reads: str = "[]", extra: str = "") -> str:
    return (f"access: http-proxy\nbase: {base}\nauth: {auth}\nreads: {reads}\nwrites: []\n"
            f"{extra}")


def _bad(base: str) -> dict[str, str]:
    return {
        "nested-duplicate-in-auth": _yaml(base, auth="{scheme: bearer, field: api_key, field: other}"),
        "nested-duplicate-in-a-route": _yaml(
            base, reads="[{method: GET, method: POST, path: /search}]"),
        "unknown-top-level-key": _yaml(base, extra="proxy_hint: pass-through\n"),
        "misspelled-top-level-key": _yaml(base).replace("reads:", "read:"),
    }


@pytest.mark.parametrize("kind", ["nested-duplicate-in-auth", "nested-duplicate-in-a-route",
                                  "unknown-top-level-key", "misspelled-top-level-key"])
def test_d5_a_declaration_with_a_nested_repeat_or_an_unread_key_is_refused_unsent(
        tmp_path, data_root, kind):
    """A merged declaration repeating a key below the top level, or holding a key the proxy does
    not read, refuses the system unsent and unread; the plain one is sent. O2, A2, O7."""
    with T.rig(tmp_path / "forge", data_root) as r:
        base = r.up.url + T.BASE_PATH
        r.t.merge({ACCESS: _bad(base)[kind]}, "bad declaration")
        r.t.publish()
        refused = r.ask()
        assert (refused["fault"], r.up.seen, r.store.reads) == ("ConfigFault", [], [])
        r.t.merge({ACCESS: _yaml(base)}, "the plain declaration")
        r.t.publish()
        control = r.ask()

    assert control["fault"] is None
    assert r.up.paths() == [f"{T.BASE_PATH}/users/x"]
