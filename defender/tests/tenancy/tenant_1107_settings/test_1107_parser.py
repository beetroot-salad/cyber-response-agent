"""The one config.env parser: quote and line rules."""
from __future__ import annotations

from defender.tests.support.shared._locations_1210 import fixture_data_root

from pathlib import Path

import pytest

from defender.runtime import run_tenant
from defender.integrations import _stub_transport as transport
from defender.tests.tenancy.tenant_1107_settings import _spec1107 as S


def _resolve(root: Path, tenant_id: str = S.PLAYGROUND_ID) -> object:
    """The REAL acceptance frame over a planted root (C1)."""
    return run_tenant.resolve_tenant(
        fixture_data_root(Path(root)), tenant_id, defender_dir=S.DEFENDER, dispatches_lead_zero=False)


def _ctx(record: object, tmp_path: Path) -> object:
    run_dir = tmp_path / "run"
    run_dir.mkdir(parents=True, exist_ok=True)
    return S.verb_context(record, run_dir, {})


def _fault_text(fn, *args, **kw) -> str:
    """Call `fn` and return the text of the `ConfigFault` it raises ('' if it raised nothing)."""
    try:
        fn(*args, **kw)
    except S.config_fault() as fault:
        return str(fault)
    return ""


def _replacing(text: str, key: str, line: str) -> str:
    """`text` with its `key=` line replaced by `line`."""
    return "".join((line if ln.startswith(f"{key}=") else ln) + "\n"
                   for ln in text.splitlines())


def test_d_one_parser_quote_rule(tmp_path):
    # rejected: the stub parser's `.strip('"').strip("'")` character-set strip
    configs = S.config_texts("q1")
    configs["cmdb"] = (_replacing(configs["cmdb"], "CMDB_URL_BASE", 'CMDB_URL_BASE="abc\'"')
                       + "CMDB_SINGLE='single-q1'\n"      # one matched single-quote pair
                       + "CMDB_NESTED=\"'nested-q1'\"\n"  # ONE pair trimmed, the inner kept
                       + 'CMDB_UNMATCHED="unmatched-q1\n')  # no matched pair: nothing trimmed
    configs["elastic"] = _replacing(configs["elastic"], "ELASTIC_EVENTS_INDEX",
                                    'ELASTIC_EVENTS_INDEX="abc\'"')
    root = tmp_path / "tenants"
    S.plant(root, marker="q1", configs=configs)

    rec = _resolve(root)
    ctx = _ctx(rec, tmp_path)

    # A stub system's load_config and elastic's load_config read the same value from the same parse.
    assert transport.load_config(ctx, "cmdb", "CMDB")["URL_BASE"] == "abc'"
    elastic_adapter = S.mod("integrations.elastic_adapter")
    assert elastic_adapter.load_config(ctx)["ELASTIC_EVENTS_INDEX"] == "abc'"
    cmdb = rec.systems["cmdb"]
    assert cmdb["CMDB_URL_BASE"] == "abc'", dict(cmdb)
    assert rec.systems["elastic"]["ELASTIC_EVENTS_INDEX"] == "abc'"
    assert cmdb["CMDB_SINGLE"] == "single-q1", dict(cmdb)
    assert cmdb["CMDB_NESTED"] == "'nested-q1'", dict(cmdb)
    assert cmdb["CMDB_UNMATCHED"] == '"unmatched-q1', dict(cmdb)


def test_s7_nf15_one_parser_line_rules(tmp_path):
    configs = S.config_texts("p15")
    # identity: an `export K=v` line and a line with no `=` (both skipped; the file still parses)
    configs["identity"] = _replacing(configs["identity"], "IDENTITY_TIMEOUT_SEC",
                                     'export IDENTITY_TIMEOUT_SEC="10"') + "no equals sign here\n"
    # threat-intel: a duplicate key (the later line) and a mid-line `#` (part of the value)
    configs["threat-intel"] = (
        'THREAT_INTEL_URL_BASE="http://threat-intel-first:1"\n'
        + _replacing(configs["threat-intel"], "THREAT_INTEL_BASTION_HOST",
                     "THREAT_INTEL_BASTION_HOST=bastion-p15 # the jump host"))
    # change-mgmt: its URL key spelt in lower case (keys match case-sensitively)
    configs["change-mgmt"] = _replacing(configs["change-mgmt"], "CHANGE_MGMT_URL_BASE",
                                        'change_mgmt_url_base="http://change-mgmt-p15:8080"')
    root = tmp_path / "tenants"
    folder = S.plant(root, marker="p15", configs=configs)
    # cmdb: a leading byte-order mark and CRLF line endings; elastic: CRLF line endings
    S.write_config(folder, "cmdb",
                   b"\xef\xbb\xbf" + configs["cmdb"].replace("\n", "\r\n").encode("utf-8"))
    S.write_config(folder, "elastic", configs["elastic"].replace("\n", "\r\n").encode("utf-8"))

    rec = _resolve(root)
    ctx = _ctx(rec, tmp_path)
    ConfigFault = S.config_fault()
    SystemConfig = S.record_type("SystemConfig")

    # BOM + CRLF: the first key is the key as written; no value ends in a carriage return.
    cmdb = rec.systems["cmdb"]
    assert isinstance(cmdb, SystemConfig), cmdb
    assert cmdb.get("CMDB_URL_BASE") == "http://cmdb-p15:8080", dict(cmdb)
    assert not any(k.startswith("﻿") for k in cmdb), list(cmdb)
    assert not any(v.endswith("\r") for v in cmdb.values()), dict(cmdb)
    assert transport.load_config(ctx, "cmdb", "CMDB") == {
        "URL_BASE": "http://cmdb-p15:8080", "BASTION_HOST": "bastion-p15", "TIMEOUT_SEC": "10"}
    assert rec.systems["elastic"]["ELASTICSEARCH_URL"] == "https://es-p15:9200"
    assert rec.systems["elastic"]["ELASTIC_SSL_VERIFY"] == "true"

    # export / no-`=` lines: skipped, not keys, and the file is not faulted for them.
    identity = rec.systems["identity"]
    assert isinstance(identity, SystemConfig), identity
    assert identity["IDENTITY_URL_BASE"] == "http://identity-p15:8080", dict(identity)
    assert "IDENTITY_TIMEOUT_SEC" not in identity, dict(identity)
    assert not any(k.startswith("export") or " " in k for k in identity), list(identity)
    missing = _fault_text(transport.load_config, ctx, "identity", "IDENTITY")
    assert "IDENTITY_TIMEOUT_SEC" in missing, missing

    # A duplicate key yields the later line; a mid-line `#` is part of the value.
    threat = rec.systems["threat-intel"]
    assert threat["THREAT_INTEL_URL_BASE"] == "http://threat-intel-p15:8080", dict(threat)
    assert threat["THREAT_INTEL_BASTION_HOST"] == "bastion-p15 # the jump host", dict(threat)

    # Case-sensitive keys: the lower-case spelling is kept verbatim and does not satisfy the
    # upper-case one, so the fault names the missing key.
    change = rec.systems["change-mgmt"]
    assert isinstance(change, SystemConfig), change
    assert change["change_mgmt_url_base"] == "http://change-mgmt-p15:8080", dict(change)
    assert "CHANGE_MGMT_URL_BASE" not in change, dict(change)
    with pytest.raises(ConfigFault) as raised:
        transport.load_config(ctx, "change-mgmt", "CHANGE_MGMT")
    assert "CHANGE_MGMT_URL_BASE" in str(raised.value), str(raised.value)
