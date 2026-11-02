"""#1163 the run record carries each system's access method and its parsed declaration or its
ConfigFault, and the #1256 run-start check marks a bad http-proxy system down without stopping
the run (A5)."""
from __future__ import annotations

import pytest

from defender._paths import adapters_under
from defender.systems import system_status
from defender.systems.verbs import read_roster
from defender.tests.integrations.credential_proxy_1163 import _adapter1163 as A
from defender.tests.integrations.credential_proxy_1163 import _harness as H
from defender.tests.integrations.credential_proxy_1163 import _tenant as T
from defender.tests.tenancy.tenant_1108_p4._support import DEFENDER, published_tenant

BASE = "http://identity.invalid/api"
BAD = {
    "good": (A.env_text("identity"), H.declaration(BASE)),
    "url-base": (A.env_text("identity", extra='IDENTITY_URL_BASE="http://identity.invalid"\n'),
                 H.declaration(BASE)),
    "bastion": (A.env_text("identity", extra='IDENTITY_BASTION_HOST="web-1"\n'),
                H.declaration(BASE)),
    "malformed": (A.env_text("identity"), "access: [http-proxy\nbase: {\n"),
    "duplicate-key": (A.env_text("identity"), A.duplicate_key_declaration(BASE)),
    "no-declaration": (A.env_text("identity"), None),
}


#: What each defect's reason must name, so a system down for being unimplemented does not pass.
WORDS = {"url-base": ("http-proxy", "URL_BASE"), "bastion": ("http-proxy", "BASTION_HOST"),
         "malformed": ("access.yaml",), "duplicate-key": ("access.yaml", "duplicate"),
         "no-declaration": ("access.yaml",)}


def _down(tmp_path, data_root, env, decl):
    files = {"settings/systems/identity/config.env": env}
    if decl is not None:
        files.update(H.access_files("identity", decl))
    with published_tenant(tmp_path / "forge", root=data_root, files=files) as t:
        record = T.run_record(t)  # resolving the record never raises on a bad declaration
        roster = read_roster(adapters_under(DEFENDER))
        return system_status.judge_run(roster, record, defender_dir=DEFENDER).down


@pytest.mark.parametrize("name", [n for n in BAD if n != "good"])
def test_a5_a_bad_http_proxy_system_is_down_at_run_start_and_the_rest_are_up(
        tmp_path, data_root, name):
    """URL_BASE or BASTION_HOST beside `http-proxy`, a malformed, duplicate-key or missing
    declaration: that system is down with a ConfigFault's reason, others stay up. A5, #1256."""
    down = _down(tmp_path, data_root, *BAD[name])
    assert "identity" in down, f"{name}: identity was judged usable"
    assert type(down["identity"]).__name__ == "NotConfigured"
    reason = down["identity"].reason
    for word in WORDS[name]:
        assert word in reason, f"{name}: the reason does not name {word!r}: {reason}"
    assert "cmdb" not in down
    assert "elastic" not in down


def test_a5_a_well_formed_http_proxy_system_is_up(tmp_path, data_root):
    """Positive control for the rows above: the same tenant with a good declaration. A5."""
    assert "identity" not in _down(tmp_path, data_root, *BAD["good"])


def test_a5_run_main_continues_with_the_bad_system_down(tmp_path, data_root):
    """Through `run.main`: a malformed declaration marks identity down at start and the run
    goes on with cmdb. A5, #1256."""
    from defender.tests.integrations.credential_proxy_1163 import test_run_start_tokens as R
    from defender.tests.tenancy.tenant_1107_settings import _spec1107 as S

    R._plant(data_root, proxy=("identity",))
    folder = data_root / S.PLAYGROUND_ID / "knowledge"
    (folder / "settings/systems/identity/access.yaml").write_text("access: [bad\n", encoding="utf-8")
    rec = S.RunRecorder(tmp_path / "run")
    rc, refused = S.drive_run(S.run_argv(S.plant_alert(tmp_path / "in"), data_root), rec,
                              signer=A.MarkedSigner(), proxy_url="http://proxy.invalid")
    assert refused is None, (rc, refused)
    assert rc == 0, (rc, refused)
    (life,) = rec.lifecycle_calls
    assert set(life["systems"].down) == {"identity"}
    assert "access.yaml" in life["systems"].down["identity"].reason
