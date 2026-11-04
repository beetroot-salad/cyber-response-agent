"""#1359 `tenant check` judges the case system the tenant names; a tenant needs no case file."""
from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
import yaml

from defender.cli import tenant as tenant_py
from defender.tests.tenancy.case_comment_1359 import _spec1359 as C
from defender.tests.tenancy.tenant_1120_piece1 import _spec1120 as H

CASE_RECORD = f"settings/{C.CASE_RECORD_REL}"
CASE_SYSTEM = "casesys"
ADAPTER = (
    "from defender.integrations import _stub_transport as transport\n\n\n"
    "def check_settings(tenant):\n"
    "    transport.check_docker_curl_settings(tenant, 'casesys', 'CASESYS')\n\n\n"
    "def health_check(ctx):\n    return {}\n\n\n"
    f"def {C.COMMENT_ACTION}(ctx, *, key, body):\n    return None\n\n\n"
    "VERBS = {'health-check': health_check}\n")
PROXY_ENV = 'CASESYS_TRANSPORT="http-proxy"\nCASESYS_TIMEOUT_SEC="5"\n'
WRITE_ROUTE = {"method": "POST", "path": "/rest/api/3/issue/*/comment"}


def _access(*, writes: tuple[dict, ...] = (WRITE_ROUTE,)) -> str:
    return json.dumps({"access": "http-proxy", "base": "https://cases.example.test",
                       "auth": {"scheme": "bearer", "field": "api_key"},
                       "reads": [], "writes": list(writes)})


@pytest.fixture(scope="module")
def script(tmp_path_factory) -> Path:
    """A tmp checkout whose adapters also hold `casesys`: a case system with a comment action and one verb."""
    checkout = H.tmp_checkout(tmp_path_factory.mktemp("c1359") / "checkout")
    H.add_adapter(checkout, CASE_SYSTEM, ADAPTER)
    return checkout / H.script_of(tenant_py).resolve().relative_to(H.REPO_ROOT)


def _folder(tmp_path: Path, *, record: str | None = None, **systems: dict[str, str]) -> Path:
    """The fixture tenant with no case-history folder, `casesys`'s verb decided (granted to nobody), the optional case-record file and `systems/<s>/<file>` texts."""
    folder = tmp_path / "tenant"
    shutil.copytree(H.FIXTURE, folder, symlinks=True)
    H.write_tenant_id_file(folder, H.TID, None)
    settings = folder / "settings"
    shutil.rmtree(settings / "systems" / C.RETIRED_SYSTEM, ignore_errors=True)
    (settings / C.CASE_RECORD_REL).unlink(missing_ok=True)
    table = settings / "verb-grants.yaml"
    doc = yaml.safe_load(table.read_text(encoding="utf-8"))
    doc["dispositions"][CASE_SYSTEM] = {"health-check": {"roles": [], "reason": "a case system; no agent reads it"}}
    table.write_text(yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")
    if record is not None:
        (settings / C.CASE_RECORD_REL).write_text(record, encoding="utf-8")
    for system, files in systems.items():
        for name, text in files.items():
            target = settings / "systems" / system / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text, encoding="utf-8")
    return folder


def _check(script: Path, folder: Path):
    return H.run_script(script, "check", "--folder", str(folder), root=None)


def _proxy_system(*, env: str = PROXY_ENV, access: str | None = None) -> dict[str, dict[str, str]]:
    return {CASE_SYSTEM: {"config.env": env, "access.yaml": access if access is not None else _access()}}


def test_o2_a_tenant_with_no_case_file_passes_check(tmp_path, script):
    """No case-record file and no case-history folder: `check --folder` and `check <id>` are clean. O2."""
    folder = _folder(tmp_path)
    assert not (folder / "settings" / C.CASE_RECORD_REL).exists()
    H.assert_clean(_check(script, folder))
    root = tmp_path / "data"
    knowledge = H.place_knowledge(root)
    shutil.rmtree(knowledge / "settings" / "systems" / C.RETIRED_SYSTEM, ignore_errors=True)
    H.assert_clean(H.check(tenant_py, root, H.TID))


def test_r1_a_case_record_naming_a_good_system_passes(tmp_path, script):
    """A case-record file naming `ticket` (docker route: no write route needed) or a configured http-proxy system with a write route is clean. r4 tenant check."""
    H.assert_clean(_check(script, _folder(tmp_path / "a", record=C.case_record_text("ticket"))))
    folder = _folder(tmp_path / "b", record=C.case_record_text(CASE_SYSTEM), **_proxy_system())
    H.assert_clean(_check(script, folder))


def test_r1_a_case_system_off_the_roster_is_a_finding_naming_the_file(tmp_path, script):
    """A case-record naming a system with no adapter fails `check`, naming `settings/case-record.yaml` and the system. r4 tenant check."""
    text = H.assert_refused(_check(script, _folder(tmp_path, record=C.case_record_text("nosuchcase"))),
                            CASE_RECORD, "nosuchcase")
    assert "Traceback" not in text


def test_r1_an_ungranted_case_system_with_bad_settings_is_a_finding_naming_its_config(tmp_path, script):
    """`check_settings` is run on the case system though no role holds it; the finding names its `config.env`. r4 tenant check."""
    broken = 'CASESYS_TRANSPORT="http-proxy"\n'
    folder = _folder(tmp_path, record=C.case_record_text(CASE_SYSTEM), **_proxy_system(env=broken))
    H.assert_refused(_check(script, folder), f"systems/{CASE_SYSTEM}/config.env")
    ticket_broken = _folder(tmp_path / "t", record=C.case_record_text("ticket"))
    (ticket_broken / "settings" / "systems" / "ticket" / "config.env").write_text("", encoding="utf-8")
    H.assert_refused(_check(script, ticket_broken), "systems/ticket/config.env")


def test_r1_an_http_proxy_case_system_must_declare_a_write_route(tmp_path, script):
    """An http-proxy case system whose `access.yaml` declares no write route is a finding naming that file. r4 tenant check."""
    folder = _folder(tmp_path, record=C.case_record_text(CASE_SYSTEM), **_proxy_system(access=_access(writes=())))
    H.assert_refused(_check(script, folder), f"systems/{CASE_SYSTEM}/access.yaml")


@pytest.mark.parametrize("record", [
    "system: [unclosed\n", "- ticket\n", "comment:\n  body: x\n", "system: 42\n", "system: ''\n",
    "system: ticket\ncomment: [x]\n",
    # D-17: `comment.body` is required (no product default), the same shape rule the record leg applies.
    "system: ticket\n", "system: ticket\ncomment: {}\n", "system: ticket\ncomment:\n  body: 7\n",
])
def test_r1_a_bad_case_record_file_is_judged_naming_the_file(tmp_path, script, record):
    """A case-record file that is not a mapping with a system name and a text `comment.body` fails `check`, naming it, as the record leg refuses it. r4 tenant check, D-17."""
    H.assert_refused(_check(script, _folder(tmp_path, record=record)), CASE_RECORD)


def test_r1_a_case_system_that_exports_no_comment_action_is_a_finding_naming_the_file(tmp_path, script):
    """A case-record naming a roster system whose adapter has no `add_case_comment` (`cmdb`) fails `check`, naming `settings/case-record.yaml` and the system, as the record leg refuses it; control: `ticket`, which exports it, is clean. D-17."""
    H.assert_clean(_check(script, _folder(tmp_path / "ok", record=C.case_record_text("ticket"))))
    text = H.assert_refused(_check(script, _folder(tmp_path / "bad", record=C.case_record_text("cmdb"))),
                            CASE_RECORD, "cmdb")
    assert "Traceback" not in text


def test_r1_a_legacy_case_history_folder_is_a_finding_naming_the_new_file(tmp_path, script):
    """`systems/case-history/` left in a tenant fails `check` naming `settings/case-record.yaml`, with or without a case-record file. r4 tenant check."""
    for label, record in (("none", None), ("with", C.case_record_text("ticket"))):
        folder = _folder(tmp_path / label, record=record)
        H.assert_clean(_check(script, folder))
        legacy = folder / "settings" / "systems" / C.RETIRED_SYSTEM
        legacy.mkdir(parents=True)
        (legacy / "mapping.yaml").write_text("comment:\n  body: x\n", encoding="utf-8")
        H.assert_refused(_check(script, folder), CASE_RECORD)


def test_r1_a_case_adapter_the_cold_read_refused_is_a_finding_naming_the_file(tmp_path, script):
    """A case-record naming a system whose `VERBS` holds the comment action (the cold read refuses the adapter) fails `check`, naming `settings/case-record.yaml` and the system; control: the same adapter without it is clean. D-17, O4."""
    refused = ADAPTER.replace("VERBS = {'health-check': health_check}\n",
                              f"VERBS = {{'health-check': health_check, '{C.COMMENT_ACTION}': health_check}}\n")
    assert refused != ADAPTER
    checkout = H.tmp_checkout(tmp_path / "checkout")
    H.add_adapter(checkout, CASE_SYSTEM, refused)
    bad_script = checkout / H.script_of(tenant_py).resolve().relative_to(H.REPO_ROOT)
    folder = _folder(tmp_path, record=C.case_record_text(CASE_SYSTEM), **_proxy_system())
    H.assert_clean(_check(script, folder))
    text = H.assert_refused(_check(bad_script, folder), CASE_RECORD, CASE_SYSTEM)
    assert "Traceback" not in text


def _script_with(tmp_path: Path, adapter: str) -> Path:
    checkout = H.tmp_checkout(tmp_path / "checkout")
    H.add_adapter(checkout, CASE_SYSTEM, adapter)
    return checkout / H.script_of(tenant_py).resolve().relative_to(H.REPO_ROOT)


@pytest.mark.parametrize(("why", "adapter"), ids=["check-crashes", "no-check"], argvalues=[
    ("a check that crashes", ADAPTER.replace(
        "    transport.check_docker_curl_settings(tenant, 'casesys', 'CASESYS')\n",
        "    return tenant.grants.missing\n")),
    ("no check at all", ADAPTER.replace("def check_settings(tenant):", "def _unused(tenant):")),
])
def test_r1_a_case_adapter_whose_check_cannot_judge_is_a_finding_not_a_crash(tmp_path, script, why, adapter):
    """A case adapter whose settings check raises something other than a settings fault, or that
    declares none, is a finding naming `settings/case-record.yaml` and the system, as run start
    judges such an adapter broken (O-5a); `check` still lists it, with no traceback. Control: the
    sound adapter is clean. #1392 review."""
    folder = _folder(tmp_path, record=C.case_record_text(CASE_SYSTEM), **_proxy_system())
    H.assert_clean(_check(script, folder))
    text = H.assert_refused(_check(_script_with(tmp_path, adapter), folder), CASE_RECORD, CASE_SYSTEM)
    assert "Traceback" not in text, why


def test_r1_a_config_env_fault_that_mentions_access_yaml_names_config_env(tmp_path, script):
    """`CASESYS_URL_BASE` set in `config.env` of an http-proxy case system is that file's fault,
    though its text tells the operator the base lives in `access.yaml`: the finding names
    `config.env`, never `access.yaml`. #1392 review."""
    env = PROXY_ENV + 'CASESYS_URL_BASE="https://cases.example.test"\n'
    folder = _folder(tmp_path, record=C.case_record_text(CASE_SYSTEM), **_proxy_system(env=env))
    text = H.assert_refused(_check(script, folder), f"systems/{CASE_SYSTEM}/config.env")
    assert f"systems/{CASE_SYSTEM}/access.yaml:" not in text, text
