"""#1359 `tenant check` judges the case system the tenant names; a tenant needs no case file.

#1366 round 4 (O9, DC8, R10): the case system and the systems are records now, judged by `check <id>` over the tenant's
records (`tenant_1108_p4/test_check_records_1366.py`); `check --folder` is a no-tenant surface that judges grants against
the catalog and reports a leftover `settings/systems/` or `case-record.yaml` as retired and ignored. The tests here that
planted system folders and a case-record file and asked `check --folder` to judge them are retired or moved (map, "Round 4
census repairs"); this file keeps the case-free folder control.
"""
from __future__ import annotations

import shutil
from pathlib import Path


from defender.cli import tenant as tenant_py
from defender.tests.tenancy.case_comment_1359 import _spec1359 as C
from defender.tests.tenancy.tenant_1120_piece1 import _spec1120 as H


def _folder(tmp_path: Path) -> Path:
    """The fixture tenant folder, for `check --folder`."""
    folder = tmp_path / "tenant"
    shutil.copytree(H.FIXTURE, folder, symlinks=True)
    H.write_tenant_id_file(folder, H.TID, None)
    return folder


def _check(script: Path, folder: Path):
    return H.run_script(script, "check", "--folder", str(folder), root=None)


def test_o2_a_tenant_with_no_case_file_passes_check(tmp_path):
    """No case-record file and no case-history folder: `check --folder` is clean. O2. (The `check <id>` half, over a data
    root's folders, moved: #1366 R10, `check <id>` reads records and needs the database;
    `test_check_records_1366.py::test_1366_o2_a_tenant_with_no_case_record_passes_check`.)"""
    folder = _folder(tmp_path)
    assert not (folder / "settings" / C.CASE_RECORD_REL).exists()
    H.assert_clean(H.run_script(H.script_of(tenant_py), "check", "--folder", str(folder), root=None))


# Retired / moved by #1366 round 4 (O9 retires the files these planted; DC8 `check --folder` judges none of them):
#  - test_r1_a_case_record_naming_a_good_system_passes, test_r1_a_case_system_off_the_roster_is_a_finding_naming_the_file:
#      clean / unknown-case-system over a case-record FILE; records: test_check_records_1366.py::test_1366_b6_..._sound_tenant
#      and ::test_1366_o1_the_case_systems_lookup_uses_the_tenants_records_not_the_checkouts_adapters.
#  - test_r1_an_ungranted_case_system_with_bad_settings..., test_r1_a_case_system_that_exports_no_comment_action...,
#    test_r1_a_config_env_fault_that_mentions_access_yaml_names_config_env: MOVED to test_check_records_1366.py
#      (test_1366_r1_an_ungranted_case_system_with_unusable_settings..., test_1366_c5_..._no_comment_action,
#      test_1366_r1_a_settings_fault_that_tells_the_operator_the_base_is_in_the_access...).
#  - test_r1_an_http_proxy_case_system_must_declare_a_write_route: ::test_1366_c5_check_reports_a_case_record_whose_system_no_longer_covers...
#  - test_r1_a_bad_case_record_file_is_judged_naming_the_file (9 shapes): a bad case-record file cannot reach a check; the store
#      refuses a bad case shape at write: tenant_1108_p4/test_system_records_1366.py::test_1366_o4_a_case_template_failing_
#      the_case_record_rules_is_refused and ::test_1366_o4_a_case_record_naming_a_file_that_is_not_a_record_is_refused.
#  - test_r1_a_legacy_case_history_folder_is_a_finding_naming_the_new_file: a leftover systems/ folder is a retired-and-ignored
#      finding: test_check_records_1366.py::test_1366_o9_check_reports_a_tenant_repos_leftover_system_folders_and_case_file...
#  - DROPPED (design gap, no equivalent): test_r1_a_case_adapter_the_cold_read_refused_is_a_finding_naming_the_file and
#    test_r1_a_case_adapter_whose_check_cannot_judge_is_a_finding_not_a_crash planted a `casesys` adapter in a tmp checkout's
#    `integrations/` (a catalog entry, not a custom reference) so `check` met an adapter whose VERBS hold the comment action,
#    whose settings check crashes, or that has none. The K2 lint (tooling/lint/tests/test_lint_catalog_declarations.py) pins the
#    catalog's declarations, not "`check` lists such an adapter as a finding, with no traceback"; the records tests use the
#    real checkout's adapters. The design does not word that outcome, so it is reported, not invented.
