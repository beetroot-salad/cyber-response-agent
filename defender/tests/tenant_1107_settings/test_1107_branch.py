"""#1107 — the branch launcher over the tenant settings record: O9's elastic refusal, the corpus
patterns and the write door read from `record.elastic` (O1), the door child's scrubbed env
(NF-31, N4), the box-mounted tenants root (MF-13), a sibling's own record (N6/MF-17) and the
foreign-view fallback (CX22).

Every launch drives the REAL `learning/branch/cli.main` over a source run planted at its tenant
location under this test's data root (`_spec1078.tenant_source`: runs-base record + stamp), with a
`--tenants-root` of our own holding a COMPLETE #1107 tenant (`_spec1107.plant`; every value carries
a marker, so a door reading the environment's or the base's default value is caught by the value).
Fakes enter only through the launcher's seams (`spawn`, `door`, `questioner`, `adapters`,
`invoke`, `preflight`, `live_tree`). The role preflight is a RECORDING TRIPWIRE answering 1: a
launch that got past every check knowable before spend reaches it and is refused there, so "the
refusal came before any preflight spend" is an observation (`calls == []`), and a control arm
that reaches it (`calls == [None]`) proves the refused arm was refused for its own reason.

The door is observed where it forks: with `door=None` the launcher builds its own, and the docker
CLI it execs is `_spec1107.DockerShim` first on this process's PATH (CX8, executed: a shim on the
PATH of the env a transport forks with receives the argv and the child's whole environment). The
shim answers the probe with an unknown context (G23/RG3), so `_probe_cluster` refuses before the
sweep and before any episode dir (G26), and the one recorded call is the door's.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from defender.learning.branch import cli, staging
from defender.learning.branch import seams as branch_seams
from defender.learning.branch.estate import registry
from defender.runtime import run_tenant
from defender.runtime.providers import api_key_vars
from defender.scripts.adapters import confinement, elastic_adapter
from defender.tests import _triplet_947 as T
from defender.tests.e2e import _lead_zero_808 as LZ
from defender.tests.tenant_1078_pass_a import _spec1078 as H
from defender.tests.tenant_1107_settings import _spec1107 as S

#: A tenant id nothing else on this box spells, so "the message names the tenant" is a finding
#: about the message and never about a default.
TID = "acme-t1107"
#: The config-shaped variables a developer's shell might carry. Cleared before every launch so a
#: value either side of an assertion is the one the test put there.
_CONFIG_VARS = ("ELASTIC_EVENTS_INDEX", "ELASTIC_ALERTS_INDEX", "ELASTICSEARCH_URL",
                "ELASTIC_SSL_VERIFY", "SOC_PLAYGROUND_ES_CONTAINER",
                "SOC_PLAYGROUND_KIBANA_CONTAINER", "SOC_PLAYGROUND_DOCKER_CONTEXT",
                "CMDB_URL_BASE", "DEFENDER_RUN_DIR", "DEFENDER_RUNS_BASE")


class _Preflight:
    """The role-model preflight seam, RECORDING and answering `rc` (1: the tripwire)."""

    def __init__(self, rc: int = 1) -> None:
        self.rc = rc
        self.calls: list[str | None] = []

    def __call__(self, model: str | None = None) -> int:
        self.calls.append(model)
        return self.rc


def _layout(tmp_path: Path, data_root: Path, monkeypatch, *, marker: str,
            root: Path | None = None) -> tuple[Path, Path, Path, Path]:
    """A branchable source at TID's tenant location, TID's complete #1107 folder under `root`
    (default `<tmp>/tenants`), and a configured episodes root. Returns (src, root, folder,
    episodes)."""
    for name in _CONFIG_VARS:
        monkeypatch.delenv(name, raising=False)
    episodes = tmp_path / "episodes"
    monkeypatch.setenv(T.EPISODES_BASE_ENV, str(episodes))
    _base, src = H.tenant_source(data_root, TID)
    root = root if root is not None else tmp_path / "tenants"
    folder = S.plant(root, TID, marker=marker)
    return src, root, folder, episodes


def _seams(**over: Any) -> dict[str, Any]:
    """Every launcher seam faked; `questioner`/`invoke` hold no replies, so reaching either is an
    AssertionError out of the fake rather than a model call."""
    seams: dict[str, Any] = {
        "spawn": T.FakeSpawn(), "door": T.FakeDoor(), "questioner": T.FakeAgent(),
        "adapters": T.FakeAdapters(), "invoke": T.FakeAgent(), "live_tree": T.source_capture(),
        "preflight": _Preflight()}
    seams.update(over)
    return seams


def _launch(src: Path, root: Path, seams: dict[str, Any]) -> tuple[Any, BaseException | None]:
    """The REAL launcher over `src`, with `--tenants-root root`. Returns (rc, None) or
    (None, the SystemExit it refused with)."""
    argv = [str(src), str(T.BRANCH_MESSAGE_ID), "--continuation-prompt", H.CONTINUATION,
            "--tenants-root", str(root)]
    try:
        return cli.main(argv, **seams), None
    except SystemExit as refused:
        return None, refused


def _resolve(root: Path) -> Any:
    """The REAL acceptance frame over a planted root (C1)."""
    return run_tenant.resolve_tenant(
        Path(root), TID, defender_dir=S.DEFENDER, dispatches_lead_zero=False)


def _sans_paths(text: str, *paths: Path) -> str:
    """`text` with every spelling of `paths` removed — the source run and both tenant folders
    carry the tenant id as a path component, so "names the tenant" is read off what is left."""
    spelled = sorted({s for p in paths for s in (str(p), str(Path(p).resolve()))},
                     key=len, reverse=True)
    for s in spelled:
        text = text.replace(s, "<path>")
    return text


def _insecure(argv: list[str]) -> bool:
    """Did the door's curl carry `-k` — as its own token, or inside the `sh -c` line the
    transport's auth arm runs curl from."""
    return any(f" {flag} " in f" {tok} " for tok in argv for flag in ("-k", "--insecure"))


def _door_call(tmp_path: Path, monkeypatch, marker: str, name: str = "docker") -> S.DockerShim:
    """A docker shim first on this process's PATH, answering every call with an unknown context.
    """
    # G23/RG3: an unknown docker context -> rc 1 'unable to resolve docker endpoint: context
    # "<name>": context not found'. The door's probe fails on it, so the launch stops at
    # `_probe_cluster` (G26: after the patterns check, before the sweep and any episode dir).
    shim = S.DockerShim(tmp_path / name, [S.context_not_found(S.context_name(marker, "elastic"))])
    # CX8: `docker` resolves on the PATH of the env the transport forks with.
    monkeypatch.setenv("PATH", shim.path_value())
    return shim


def _episode_dir(episodes: Path) -> Path:
    return episodes / cli.episode_id_for(T.SOURCE_RUN_ID, T.BRANCH_MESSAGE_ID)


# ---------------------------------------------------------------------------------------------
# O9 — the launcher refuses a tenant with no usable Elastic part, naming it, before anything.
# ---------------------------------------------------------------------------------------------

def test_o9_no_elastic_refused(tmp_path, data_root, monkeypatch):
    """The branch launcher, over a source run whose tenant has no systems/elastic/ folder, refuses with
    LauncherRefused. The message names the tenant and says 'no elastic system configured'. The
    refusal comes before any episode dir exists, and before the questioner or any preflight spend."""
    # rejected: today's StagingRefused 'this deployment configures no corpus pattern', raised
    # inside preflight_episode without the tenant (CX14)
    shim = _door_call(tmp_path, monkeypatch, "o9n")
    src, root, folder, episodes = _layout(tmp_path, data_root, monkeypatch, marker="o9n")
    shutil.rmtree(S.config_path(folder, "elastic").parent)
    seams = _seams(door=None)

    rc, refused = _launch(src, root, seams)

    assert refused is not None, f"the launcher accepted a tenant with no elastic system (rc={rc})"
    assert isinstance(refused, cli.LauncherRefused), f"not the launcher's refusal: {refused!r}"
    text = H.refusal_text(refused)
    assert S.NO_ELASTIC in text, f"the refusal does not say {S.NO_ELASTIC!r}: {text!r}"
    assert TID in _sans_paths(text, src, root / TID, data_root / TID), \
        f"the refusal does not name the tenant {TID!r}: {text!r}"
    assert H.entries(episodes) == [], f"an episode dir exists: {H.entries(episodes)}"
    assert seams["preflight"].calls == [], "the role preflight was spent before the refusal"
    assert seams["questioner"].prompts == [], "the questioner was asked before the refusal"
    assert seams["spawn"].launches == [], "a sibling started before the refusal"
    assert shim.calls() == [], f"the cluster was contacted before the refusal: {shim.calls()}"
    record = _resolve(root)
    assert record.elastic is None, f"record.elastic for a tenant with no folder: {record.elastic!r}"


def test_o9_bad_elastic_refused(tmp_path, data_root, monkeypatch):
    """Over a tenant whose elastic config.env lacks ELASTIC_ES_CONTAINER, the launcher refuses with a
    message that names the tenant and says 'elastic config is bad: <the ConfigFault's text>'. The
    refusal comes before any episode dir exists."""
    shim = _door_call(tmp_path, monkeypatch, "o9b")
    src, root, folder, episodes = _layout(tmp_path, data_root, monkeypatch, marker="o9b")
    S.drop_key(folder, "elastic", "ELASTIC_ES_CONTAINER")
    seams = _seams(door=None)

    rc, refused = _launch(src, root, seams)

    assert refused is not None, f"the launcher accepted a bad elastic config (rc={rc})"
    assert isinstance(refused, cli.LauncherRefused), f"not the launcher's refusal: {refused!r}"
    text = H.refusal_text(refused)
    assert S.BAD_ELASTIC in text, f"the refusal does not say {S.BAD_ELASTIC!r}: {text!r}"
    assert TID in _sans_paths(text, src, root / TID, data_root / TID), \
        f"the refusal does not name the tenant {TID!r}: {text!r}"
    fault = _resolve(root).elastic
    assert isinstance(fault, S.config_fault()), f"record.elastic is not a ConfigFault: {fault!r}"
    assert f"{S.BAD_ELASTIC}: {fault}" in text, \
        f"the refusal does not carry the ConfigFault's text {str(fault)!r}: {text!r}"
    assert H.entries(episodes) == [], f"an episode dir exists: {H.entries(episodes)}"
    assert seams["preflight"].calls == [], "the role preflight was spent before the refusal"
    assert shim.calls() == [], f"the cluster was contacted before the refusal: {shim.calls()}"


def test_branch_refusal_names_the_elastic_fault(tmp_path, data_root, monkeypatch):
    """The branch refusal names the tenant and says which: "no elastic system configured", or "elastic
    config is bad: <fault>" carrying the fault's text; it reaches the operator launching the branch
    before any episode dir exists."""
    # THE OPERATOR'S CHANNEL: the launcher run as the command it is, its refusal read off the
    # process's stderr. The shim is first on the child's PATH, so nothing reaches a real docker.
    shim = S.DockerShim(tmp_path / "docker")
    src, root, folder, episodes = _layout(tmp_path, data_root, monkeypatch, marker="s073")
    env = shim.env(PYTHONPATH=str(S.REPO_ROOT))
    for key in api_key_vars():
        env.pop(key, None)
    argv = [sys.executable,
            str(S.DEFENDER / "learning" / "branch" / "cli.py"),
            str(src), str(T.BRANCH_MESSAGE_ID), "--continuation-prompt", H.CONTINUATION,
            "--tenants-root", str(root)]
    elastic_text = S.config_path(folder, "elastic").read_text(encoding="utf-8")

    # Arm 1: no systems/elastic/ folder.
    shutil.rmtree(S.config_path(folder, "elastic").parent)
    none_arm = subprocess.run(argv, env=env, capture_output=True, text=True, timeout=180,
                              check=False)
    # Arm 2: the folder back, without ELASTIC_ES_CONTAINER.
    S.write_config(folder, "elastic", elastic_text)
    S.drop_key(folder, "elastic", "ELASTIC_ES_CONTAINER")
    bad_arm = subprocess.run(argv, env=env, capture_output=True, text=True, timeout=180,
                             check=False)

    for arm, proc in (("no folder", none_arm), ("bad config", bad_arm)):
        assert proc.returncode != 0, f"{arm}: the launcher exited 0: {proc.stderr[-2000:]}"
        assert TID in _sans_paths(proc.stderr, src, root / TID, data_root / TID), \
            f"{arm}: stderr does not name the tenant {TID!r}: {proc.stderr[-2000:]}"
    assert S.NO_ELASTIC in none_arm.stderr, \
        f"no-folder arm: stderr does not say {S.NO_ELASTIC!r}: {none_arm.stderr[-2000:]}"
    fault = _resolve(root).elastic
    assert isinstance(fault, S.config_fault()), f"record.elastic is not a ConfigFault: {fault!r}"
    assert f"{S.BAD_ELASTIC}: {fault}" in bad_arm.stderr, \
        f"bad arm: stderr does not carry {S.BAD_ELASTIC!r} + the fault: {bad_arm.stderr[-2000:]}"
    assert H.entries(episodes) == [], f"an episode dir exists: {H.entries(episodes)}"
    assert shim.calls() == [], f"the cluster was contacted: {shim.calls()}"


def test_s7_mf7a_launcher_refuses_elastic_without_docker_exec(tmp_path, data_root, monkeypatch):
    """A tenant whose elastic config.env carries every listed Elastic key but no ELASTIC_TRANSPORT (or
    one other than docker-exec) has record.elastic a ConfigFault: the branch launcher refuses with
    "elastic config is bad: <fault>" naming the tenant before any episode dir exists, and
    lead-zero's item 1 reports unavailable."""
    monkeypatch.setenv("PATH", S.DockerShim(tmp_path / "docker").path_value())
    src, root, folder, episodes = _layout(tmp_path, data_root, monkeypatch, marker="mf7a")

    # Positive control: the same complete file WITH `ELASTIC_TRANSPORT=docker-exec` launches
    # past every check before spend (reaches the tripwire), and is an ElasticSettings.
    control = _seams()
    _rc, control_refused = _launch(src, root, control)
    assert control["preflight"].calls == [None], \
        f"the control launch never reached the role preflight: {control_refused!r}"
    assert isinstance(_resolve(root).elastic, S.record_type("ElasticSettings")), \
        "the complete file is not a view"

    for arm, edit in (("absent", lambda: S.drop_key(folder, "elastic", "ELASTIC_TRANSPORT")),
                      ("ssh", lambda: S.set_key(folder, "elastic", "ELASTIC_TRANSPORT", "ssh"))):
        edit()
        fault = _resolve(root).elastic
        assert isinstance(fault, S.config_fault()), \
            f"TRANSPORT {arm}: record.elastic is not a ConfigFault: {fault!r}"
        seams = _seams()
        rc, refused = _launch(src, root, seams)
        assert isinstance(refused, cli.LauncherRefused), \
            f"TRANSPORT {arm}: not refused by the launcher (rc={rc}, {refused!r})"
        text = H.refusal_text(refused)
        assert f"{S.BAD_ELASTIC}: {fault}" in text, \
            f"TRANSPORT {arm}: the refusal does not carry the fault: {text!r}"
        assert TID in _sans_paths(text, src, root / TID, data_root / TID), \
            f"TRANSPORT {arm}: the refusal does not name the tenant: {text!r}"
        assert seams["preflight"].calls == [], f"TRANSPORT {arm}: the preflight was spent"
        assert seams["door"].calls == [], f"TRANSPORT {arm}: the door was used: {seams['door'].ops}"
        assert not _episode_dir(episodes).exists(), f"TRANSPORT {arm}: an episode dir exists"
        S.set_key(folder, "elastic", "ELASTIC_TRANSPORT", S.DOCKER_EXEC)

    # Lead-zero's item 1 over the same tenant, for an alert with no signal_index: the complete
    # tenant issues the shell fetch (the channel can see the difference) ...
    tenant_dir = S.tenant_folder_of(root, TID)
    ok = LZ.run(tmp_path / "lz-ok", alert=LZ.alert_doc(signal_index=None), tenant=tenant_dir)
    assert ok.rec.calls, "control: item 1 issued no backend call over the complete tenant"
    # ... and the one with no ELASTIC_TRANSPORT reports unavailable, issuing none. The note names
    # the cause (F11, auto: 'elastic config is bad') — the control's own section can say
    # "unavailable" too (the fetch found nothing), so the cause and the call count discriminate.
    S.drop_key(folder, "elastic", "ELASTIC_TRANSPORT")
    bad = LZ.run(tmp_path / "lz-bad", alert=LZ.alert_doc(signal_index=None), tenant=tenant_dir)
    assert bad.rec.calls == [], f"item 1 issued {len(bad.rec.calls)} backend call(s)"
    assert LZ.UNAVAILABLE in bad.section(), \
        f"item 1 did not report unavailable: {bad.section()[:600]!r}"
    assert S.BAD_ELASTIC in bad.section(), \
        f"item 1's note does not name the cause: {bad.section()[:600]!r}"


def test_s7_mf13_launcher_refuses_box_mounted_tenants_root(tmp_path, data_root, monkeypatch):
    """The branch launcher passes its box-mounted trees (the episodes base, and the runs base it
    resolves at cli.py:1374) to resolve_tenant as box_mounted: a tenants root inside either is
    refused at launch with LauncherRefused naming the tenant, before any episode dir exists and
    before any world is staged."""
    monkeypatch.setenv("PATH", S.DockerShim(tmp_path / "docker").path_value())
    src, outside, _folder, episodes = _layout(tmp_path, data_root, monkeypatch, marker="mf13")

    # Positive control: the same tenant under a root outside both trees passes every check
    # before spend.
    control = _seams()
    _launch(src, outside, control)
    assert control["preflight"].calls == [None], \
        "the control launch (tenants root outside both trees) never reached the role preflight"

    runs_base = H.runs_dir(data_root, TID)
    for arm, root in (("inside the episodes base", episodes / "tenants-in-episodes"),
                      ("inside the runs base", runs_base / "tenants-in-runs")):
        S.plant(root, TID, marker="mf13")
        resolved = run_tenant.resolve_tenant(root, TID, defender_dir=S.DEFENDER,
                                             dispatches_lead_zero=False)
        assert resolved.tenant_id == TID, f"{arm}: the resolver alone refuses this root"
        seams = _seams()
        rc, refused = _launch(src, root, seams)
        assert isinstance(refused, cli.LauncherRefused), \
            f"{arm}: the launcher accepted a box-mounted tenants root (rc={rc}, {refused!r})"
        text = H.refusal_text(refused)
        assert TID in _sans_paths(text, src, root / TID, outside / TID, data_root / TID), \
            f"{arm}: the refusal does not name the tenant: {text!r}"
        assert seams["preflight"].calls == [], f"{arm}: the role preflight was spent: {text!r}"
        assert seams["door"].calls == [], f"{arm}: a world was staged: {seams['door'].ops}"
        assert seams["questioner"].prompts == [], f"{arm}: the questioner was asked"
        assert not _episode_dir(episodes).exists(), f"{arm}: an episode dir exists"


# ---------------------------------------------------------------------------------------------
# PG-1 / PG-1a — a bare `*` corpus pattern is refused at launch, by the launch-time check alone.
# ---------------------------------------------------------------------------------------------

def test_s7pg_bare_star_events_index_refused_at_launch(tmp_path, data_root, monkeypatch):
    """A tenant whose elastic config.env sets ELASTIC_EVENTS_INDEX to exactly `*` is refused at branch
    launch by check_configured_patterns, with a reason that names the key and says a bare `*` would
    widen confinement to every index the cluster serves, before any episode dir exists. A trailing
    wildcard such as acme-* is accepted as today (a mid-pattern wildcard such as logs-*-prod is
    already refused at base, and this rule does not change that), and the resolver still carries
    `*` into record.elastic (no resolve-time validation, NF-18): the refusal is the launch-time
    check's alone, in the same class as its CHANGE-ME refusal (G49/F23)."""
    monkeypatch.setenv("PATH", S.DockerShim(tmp_path / "docker").path_value())
    src, root, folder, episodes = _layout(tmp_path, data_root, monkeypatch, marker="pgev")
    alerts = "pgev-alerts-*"  # the fixture's own value (`config_texts`: "<marker>-alerts-*")

    # Any other wildcard shape is accepted as today — by the launch-time check itself, and by a
    # launch over it, which passes every check before spend.
    accepted = staging.check_configured_patterns(("acme-*", alerts))
    assert accepted == ("acme-*", alerts), f"acme-* is not accepted: {accepted!r}"
    S.set_key(folder, "elastic", "ELASTIC_EVENTS_INDEX", "acme-*")
    control = _seams()
    _launch(src, root, control)
    assert control["preflight"].calls == [None], "the acme-* launch never reached the preflight"

    S.set_key(folder, "elastic", "ELASTIC_EVENTS_INDEX", "*")
    record = _resolve(root)
    assert record.elastic.events_index == "*", \
        f"the resolver did not carry `*`: {record.elastic!r}"
    seams = _seams()
    rc, refused = _launch(src, root, seams)
    assert isinstance(refused, cli.LauncherRefused), f"a bare `*` launched (rc={rc}, {refused!r})"
    text = H.refusal_text(refused)
    assert "ELASTIC_EVENTS_INDEX" in text, f"the refusal does not name the key: {text!r}"
    assert "`*`" in text or "'*'" in text or '"*"' in text, \
        f"the refusal does not name the bare `*`: {text!r}"
    # The seed's wording: a bare `*` "would widen confinement to every index the cluster serves".
    assert "every index" in text, f"the refusal does not say it widens to every index: {text!r}"
    assert seams["preflight"].calls == [], "the role preflight was spent before the refusal"
    assert not _episode_dir(episodes).exists(), "an episode dir exists"


def test_s7pg_bare_star_alerts_index_refused_at_launch(tmp_path, data_root, monkeypatch):
    """A tenant whose elastic config.env sets ELASTIC_ALERTS_INDEX to exactly `*` is refused at branch
    launch by check_configured_patterns under the same rule as ELASTIC_EVENTS_INDEX: a reason that
    names the key and says a bare `*` would widen confinement to every index the cluster serves,
    before any episode dir exists. A trailing wildcard such as acme-alerts-* is accepted as today,
    and the resolver still carries `*` into record.elastic (NF-18)."""
    monkeypatch.setenv("PATH", S.DockerShim(tmp_path / "docker").path_value())
    src, root, folder, episodes = _layout(tmp_path, data_root, monkeypatch, marker="pgal")
    events = "pgal-events-*"  # the fixture's own value (`config_texts`: "<marker>-events-*")

    accepted = staging.check_configured_patterns((events, "acme-alerts-*"))
    assert accepted == (events, "acme-alerts-*"), f"acme-alerts-* is not accepted: {accepted!r}"
    S.set_key(folder, "elastic", "ELASTIC_ALERTS_INDEX", "acme-alerts-*")
    control = _seams()
    _launch(src, root, control)
    assert control["preflight"].calls == [None], \
        "the acme-alerts-* launch never reached the preflight"

    S.set_key(folder, "elastic", "ELASTIC_ALERTS_INDEX", "*")
    record = _resolve(root)
    assert record.elastic.alerts_index == "*", \
        f"the resolver did not carry `*`: {record.elastic!r}"
    seams = _seams()
    rc, refused = _launch(src, root, seams)
    assert isinstance(refused, cli.LauncherRefused), f"a bare `*` launched (rc={rc}, {refused!r})"
    text = H.refusal_text(refused)
    assert "ELASTIC_ALERTS_INDEX" in text, f"the refusal does not name the key: {text!r}"
    assert "`*`" in text or "'*'" in text or '"*"' in text, \
        f"the refusal does not name the bare `*`: {text!r}"
    assert "every index" in text, f"the refusal does not say it widens to every index: {text!r}"
    assert seams["preflight"].calls == [], "the role preflight was spent before the refusal"
    assert not _episode_dir(episodes).exists(), "an episode dir exists"


def test_s60_elastic_events_index_values_carried_forward(tmp_path, data_root, monkeypatch):
    """ELASTIC_EVENTS_INDEX is not validated beyond presence (NF-18): a plain (non-wildcard) pattern is
    carried verbatim; a bare '*' is carried verbatim into record.elastic at resolve (no resolve-time
    value validation, NF-18) and is then refused at branch launch by check_configured_patterns
    (s7pg_bare_star_events_index_refused_at_launch); an upper-case/CHANGE-ME pattern is still
    refused by check_configured_patterns at launch (G49/F23) over the migrated record-based systems
    path."""
    monkeypatch.setenv("PATH", S.DockerShim(tmp_path / "docker").path_value())
    src, root, folder, episodes = _layout(tmp_path, data_root, monkeypatch, marker="s60e")
    view_type = S.record_type("ElasticSettings")

    # A plain (no trailing wildcard) pattern: carried verbatim, the part still a view.
    S.set_key(folder, "elastic", "ELASTIC_EVENTS_INDEX", "s60e-events")
    plain = _resolve(root).elastic
    assert isinstance(plain, view_type), f"a plain pattern faulted the part: {plain!r}"
    assert plain.events_index == "s60e-events", f"not carried verbatim: {plain.events_index!r}"

    # A bare `*`: carried at resolve, refused at launch before any spend.
    S.set_key(folder, "elastic", "ELASTIC_EVENTS_INDEX", "*")
    star = _resolve(root).elastic
    assert isinstance(star, view_type), f"`*` faulted the part at resolve: {star!r}"
    assert star.events_index == "*", f"`*` not carried verbatim: {star.events_index!r}"
    seams = _seams()
    _rc, refused = _launch(src, root, seams)
    assert isinstance(refused, cli.LauncherRefused), f"`*` was not refused at launch: {refused!r}"
    assert seams["preflight"].calls == [], "`*`: the role preflight was spent before the refusal"

    # CHANGE-ME: carried at resolve, refused at launch (G49/F23: upper case). A VALID pattern is
    # exported under the same key, so a launch still reading the environment over the file
    # would pass the check — the refusal is observed over the record-based path.
    S.set_key(folder, "elastic", "ELASTIC_EVENTS_INDEX", "CHANGE-ME")
    monkeypatch.setenv("ELASTIC_EVENTS_INDEX", "s60e-env-*")
    placeholder = _resolve(root).elastic
    assert isinstance(placeholder, view_type), f"CHANGE-ME faulted the part: {placeholder!r}"
    assert placeholder.events_index == "CHANGE-ME", \
        f"CHANGE-ME not carried verbatim: {placeholder.events_index!r}"
    seams = _seams()
    _rc, refused = _launch(src, root, seams)
    assert isinstance(refused, cli.LauncherRefused), \
        f"CHANGE-ME was not refused at launch: {refused!r}"
    assert "CHANGE-ME" in H.refusal_text(refused), \
        f"the refusal is not about the CHANGE-ME pattern: {H.refusal_text(refused)!r}"
    assert seams["preflight"].calls == [], "CHANGE-ME: the role preflight was spent"
    assert not _episode_dir(episodes).exists(), "an episode dir exists"


# ---------------------------------------------------------------------------------------------
# O1 — the launcher's patterns and write door come from the tenant file, never the environment.
# ---------------------------------------------------------------------------------------------

def test_o1_staged_patterns_ignore_env(tmp_path, data_root, monkeypatch):
    """With ELASTIC_EVENTS_INDEX and ELASTIC_ALERTS_INDEX exported, the branch launcher's configured
    patterns and a sibling's foreign-view fallback are the tenant file's patterns."""
    monkeypatch.setenv("PATH", S.DockerShim(tmp_path / "docker").path_value())
    src, root, _folder, episodes = _layout(tmp_path, data_root, monkeypatch, marker="o1s")
    env_events, env_alerts = "o1env-events-*", "o1env-alerts-*"
    monkeypatch.setenv("ELASTIC_EVENTS_INDEX", env_events)
    monkeypatch.setenv("ELASTIC_ALERTS_INDEX", env_alerts)
    file_events, file_alerts = "o1s-events-*", "o1s-alerts-*"

    # The launcher: its cluster probe counts `patterns[0]`, the configured events pattern.
    # G26: the probe runs after the patterns check and before the sweep and any episode dir; the
    # door's first connection fails (TransportFault), so the launch stops right there.
    door = T.FakeDoor(fault=T.Fault(raise_after=0))
    _rc, refused = _launch(src, root, _seams(door=door, preflight=T.no_preflight))
    assert door.calls, f"the launcher never probed the cluster: {refused!r}"
    assert door.ops[0] == ("count", file_events), \
        f"the launcher's configured events pattern is not the file's: {door.ops}"

    # A sibling's foreign-view fallback: a world with no manifest record, served under a context
    # carrying the record (and the exported patterns in its env).
    record = _resolve(root)
    run_dir = tmp_path / "sibling-run"
    run_dir.mkdir()
    ctx = S.verb_context(record, run_dir, {**os.environ})
    world = SimpleNamespace(world_id="fvb", touches=("elastic",),
                            family=SimpleNamespace(configured_patterns=()))
    for own in (file_events, file_alerts):
        registry.refuse_a_foreign_world_view(
            world, "elastic", "query",
            {"index": confinement.world_view(own, "fvb"), "native_query": "*"}, ctx)
    for foreign in (env_events, env_alerts):
        with pytest.raises(confinement.ConfinementFault):
            registry.refuse_a_foreign_world_view(
                world, "elastic", "query",
                {"index": confinement.world_view(foreign, "fvb"), "native_query": "*"}, ctx)


def test_o1_write_door_ignores_env(tmp_path, data_root, monkeypatch):
    """With ELASTICSEARCH_URL, ELASTIC_SSL_VERIFY and SOC_PLAYGROUND_ES_CONTAINER exported, and also
    present in the caller's ctx env, the write door's base URL, TLS posture and container are the
    tenant file's."""
    shim = _door_call(tmp_path, monkeypatch, "o1w")
    src, root, folder, episodes = _layout(tmp_path, data_root, monkeypatch, marker="o1w")
    # The file: https://es-o1w:9200, ELASTIC_SSL_VERIFY=true (secure), container es-o1w.
    env_url = "https://o1-env-es.invalid:1"
    monkeypatch.setenv("ELASTICSEARCH_URL", env_url)
    monkeypatch.setenv("ELASTIC_SSL_VERIFY", "false")
    monkeypatch.setenv("SOC_PLAYGROUND_ES_CONTAINER", "o1-env-container")

    _launch(src, root, _seams(door=None, preflight=T.no_preflight))

    calls = shim.calls()
    assert calls, "the write door never forked docker"
    argv, child = calls[0]["argv"], calls[0]["env"]
    # Positive precondition: the exported values WERE in the env the door's child was handed.
    assert child.get("ELASTICSEARCH_URL") == env_url, \
        "the exported ELASTICSEARCH_URL is not in the door's ctx env — the channel is blind"
    assert (S.curl_url(argv) or "").startswith("https://es-o1w:9200"), \
        f"the door's base URL is not the file's: {S.curl_url(argv)!r}"
    assert S.exec_target(argv) == S.es_container("o1w"), \
        f"the door's container is not the file's: {S.exec_target(argv)!r}"
    assert not _insecure(argv), f"the door is insecure though the file says true: {argv}"


# ---------------------------------------------------------------------------------------------
# NF-31 / N4 — the door child's environment: scrubbed of provider keys, carrying what docker needs.
# ---------------------------------------------------------------------------------------------

def test_d_door_child_env_scrubbed(tmp_path, data_root, monkeypatch):
    """The launcher's entry point builds the write door's docker child environment with run_common's
    provider-key scrub and passes it in. A provider API key variable present in the launching
    process's environment is absent from the door child's environment. It carries no
    DEFENDER_RUN_DIR or DEFENDER_RUNS_BASE naming a run that does not exist yet (NF-31, auto).
    Whether docker's own steering variables reach the door child is left unspecified (MF-3: waived
    to the per-tenant hands box follow-up) and is not asserted here."""
    shim = _door_call(tmp_path, monkeypatch, "dscr")
    src, root, _folder, episodes = _layout(tmp_path, data_root, monkeypatch, marker="dscr")
    provider_key = sorted(api_key_vars())[0]
    provider_value = "t1107-provider-key-value"
    monkeypatch.setenv(provider_key, provider_value)
    monkeypatch.setenv("T1107_DOOR_MARK", "door-mark-1107")

    _launch(src, root, _seams(door=None, preflight=T.no_preflight))

    calls = shim.calls()
    assert calls, "the write door never forked docker"
    child = calls[0]["env"]
    # Positive precondition: the launching process's env reaches the door child at all.
    assert child.get("T1107_DOOR_MARK") == "door-mark-1107", \
        "the launching env's own variable is not in the door child's env — the channel is blind"
    assert provider_key not in child, f"the provider key {provider_key} reached the door child"
    assert provider_value not in child.values(), "the provider key's value reached the door child"
    assert "DEFENDER_RUN_DIR" not in child, f"DEFENDER_RUN_DIR: {child.get('DEFENDER_RUN_DIR')}"
    assert "DEFENDER_RUNS_BASE" not in child, \
        f"DEFENDER_RUNS_BASE: {child.get('DEFENDER_RUNS_BASE')}"
    # AF-8: MF-3's waiver leaves docker's steering variables (DOCKER_HOST and the like)
    # unspecified — pinning either fate would harden a deferred gap into a contract.
    assert not _episode_dir(episodes).exists(), "the door ran after an episode dir existed"


def test_d_launcher_door_transport_seam(tmp_path, data_root, monkeypatch):
    """The branch launcher takes a transport for the write door it builds (the door_transport
    seam): with the door left to the launcher, every door call goes through that transport,
    handed a context that carries the episode tenant's record, so the door addresses that
    record's own elastic docker context and container. It is the door lane's one injection seam:
    a secret-bearing door call resolves its secret from that same record."""
    # Minted at the Phase F re-open (O4 lanes, human): without it the door lane is reachable only
    # by building a door OUTSIDE the launcher, which never exercises the launcher's own wiring.
    import inspect

    from defender.scripts.adapters import _stub_transport

    assert S.DOOR_TRANSPORT_KW in inspect.signature(cli.main).parameters, (
        f"the launcher takes no {S.DOOR_TRANSPORT_KW}= transport for the door it builds: "
        f"{inspect.signature(cli.main)}")
    # AP3: the daemon's own answer for a container that is not there — the probe fails on it, so
    # the launch stops at `_probe_cluster` (G26), before the sweep and any episode dir.
    shim = S.DockerShim(tmp_path / "docker", [S.no_such_container(S.es_container("dts"))])
    monkeypatch.setenv("PATH", shim.path_value())
    src, root, _folder, episodes = _layout(tmp_path, data_root, monkeypatch, marker="dts")
    record = _resolve(root)
    seen: list[Any] = []

    def door_transport(ctx: Any, container: str, url: str, **kw: Any) -> tuple[int, str, str]:
        seen.append((ctx, container, url))
        return _stub_transport.docker_exec_curl(ctx, container, url, **kw)

    rc, refused = _launch(src, root, _seams(door=None, **{S.DOOR_TRANSPORT_KW: door_transport}))

    assert seen, f"the launcher's door never called the injected transport (rc={rc}, {refused!r})"
    assert len(shim.calls()) == len(seen), "a door docker call bypassed the injected transport"
    for ctx, container, _url in seen:
        carried = S.record_on(ctx)
        assert carried.tenant_id == record.tenant_id, \
            f"the door's context carries another tenant's record: {carried!r}"
        assert carried.dir == record.dir, f"the door's context carries another folder: {carried!r}"
        assert container == S.es_container("dts"), f"the door addressed {container!r}"
    for argv in (c["argv"] for c in shim.calls()):
        assert S.context_of(argv) == S.context_name("dts", "elastic"), \
            f"the door's child is not on the record's elastic context: {argv}"
    assert isinstance(refused, cli.LauncherRefused), f"the probe's failure did not refuse: {refused!r}"
    assert not _episode_dir(episodes).exists(), "an episode dir exists after the probe refused"

def test_d_door_child_env_carries_path(tmp_path, data_root, monkeypatch):
    """The same door child's environment carries the launching process's PATH, HOME and DOCKER_CONFIG
    (N4, NF-31). The scrub removes provider keys and keeps what docker needs."""
    shim = _door_call(tmp_path, monkeypatch, "dpath")
    src, root, _folder, _episodes = _layout(tmp_path, data_root, monkeypatch, marker="dpath")
    home, docker_config = tmp_path / "home-1107", tmp_path / "docker-config-1107"
    home.mkdir()
    docker_config.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("DOCKER_CONFIG", str(docker_config))
    provider_key = sorted(api_key_vars())[0]
    monkeypatch.setenv(provider_key, "t1107-provider-key-value")
    launch_path = os.environ["PATH"]

    _launch(src, root, _seams(door=None, preflight=T.no_preflight))

    calls = shim.calls()
    assert calls, "the write door never forked docker"
    child = calls[0]["env"]
    assert launch_path in child.get("PATH", ""), \
        f"the launching PATH is not in the door child's PATH: {child.get('PATH')!r}"
    assert child.get("HOME") == str(home), f"HOME: {child.get('HOME')!r}"
    assert child.get("DOCKER_CONFIG") == str(docker_config), \
        f"DOCKER_CONFIG: {child.get('DOCKER_CONFIG')!r}"
    assert provider_key not in child, f"the scrub kept the provider key {provider_key}"


def test_s60_elastic_ssl_verify_values_pass_through(tmp_path, data_root, monkeypatch):
    """ELASTIC_SSL_VERIFY is not validated (F3/NF-18, presence-only): 'false' toggles the door
    insecure, 'TRUE' (uppercase) toggles it secure because .lower() == 'true', and 'CHANGE-ME' is
    carried through as a literal (insecure) value with no rejection. Three cases, one demand."""
    src, root, folder, _episodes = _layout(tmp_path, data_root, monkeypatch, marker="ssl")
    for value, insecure in (("false", True), ("TRUE", False), ("CHANGE-ME", True)):
        S.set_key(folder, "elastic", "ELASTIC_SSL_VERIFY", value)
        carried = _resolve(root).elastic
        assert carried.ssl_verify == value, \
            f"ELASTIC_SSL_VERIFY={value!r} not carried as the raw string: {carried!r}"
        shim = _door_call(tmp_path, monkeypatch, "ssl", name=f"docker-{value}")
        _rc, refused = _launch(src, root, _seams(door=None, preflight=T.no_preflight))
        calls = shim.calls()
        assert calls, f"ELASTIC_SSL_VERIFY={value!r}: the launch never reached the door " \
                      f"({refused!r})"
        assert "ELASTIC_SSL_VERIFY" not in H.refusal_text(refused), \
            f"ELASTIC_SSL_VERIFY={value!r} was rejected: {H.refusal_text(refused)!r}"
        assert S.exec_target(calls[0]["argv"]) == S.es_container("ssl"), \
            f"not the tenant's door: {calls[0]['argv']}"
        assert _insecure(calls[0]["argv"]) is insecure, \
            f"ELASTIC_SSL_VERIFY={value!r}: insecure should be {insecure}: {calls[0]['argv']}"


# ---------------------------------------------------------------------------------------------
# GR7 / N6 — siblings: the launcher's pass-through env, and a sibling's own record.
# ---------------------------------------------------------------------------------------------

def test_s60_launch_one_env_is_passthrough(tmp_path, data_root, monkeypatch):
    """learning/branch/cli.py's launch_one closure passes os.environ to each sibling's spawn as a
    wholesale copy, with no per-key lookup or branch on any tenant-config-shaped name -- a sibling
    launch is unaffected by a config key exported in the launching process's environment, the same
    guarantee O1's other tests pin for the adapters."""
    for name in _CONFIG_VARS:
        monkeypatch.delenv(name, raising=False)
    H.make_tenant(data_root, TID)
    root = tmp_path / "tenants"
    S.plant(root, TID, marker="gr7")

    quiet_ep = T.episode(tmp_path / "quiet", root=tmp_path / "quiet" / "episodes")
    quiet = T.FakeSpawn()
    cli.start_family(quiet_ep, ["b"], spawn=quiet, tenant_id=TID, tenants_root=root)
    quiet_environ = dict(os.environ)

    exported = {"CMDB_URL_BASE": "http://gr7-env-cmdb.invalid:1",
                "ELASTIC_EVENTS_INDEX": "gr7env-events-*"}
    for key, value in exported.items():
        monkeypatch.setenv(key, value)
    loud_ep = T.episode(tmp_path / "loud", root=tmp_path / "loud" / "episodes")
    loud = T.FakeSpawn()
    cli.start_family(loud_ep, ["b"], spawn=loud, tenant_id=TID, tenants_root=root)
    loud_environ = dict(os.environ)

    assert len(quiet.launches) == 1, (quiet.launches, loud.launches)
    assert len(loud.launches) == 1, (quiet.launches, loud.launches)
    q, lo = quiet.launches[0], loud.launches[0]
    # Positive precondition: the exported config key WAS in what the sibling was handed.
    assert lo["env"].get("CMDB_URL_BASE") == exported["CMDB_URL_BASE"], \
        "the exported key is not in the sibling's env — the channel is blind"
    # A wholesale copy of the launching environment, nothing selected, dropped or added ...
    assert q["env"] == quiet_environ, "the quiet sibling's env is not os.environ copied whole"
    assert lo["env"] == loud_environ, "the loud sibling's env is not os.environ copied whole"
    # ... and the launch is otherwise unaffected by the exported key.
    assert [a.replace(str(loud_ep), "<ep>") for a in lo["argv"]] == \
        [a.replace(str(quiet_ep), "<ep>") for a in q["argv"]], (q["argv"], lo["argv"])
    assert lo["kw"] == q["kw"], (q["kw"], lo["kw"])


def test_s7_mf17_sibling_resolves_its_own_record(tmp_path, data_root, monkeypatch):
    """An elastic config.env edited between the launcher's O9 check and a sibling's start: the sibling
    builds its own record at its own start (N6), so an edit that makes its Elastic part bad makes
    that sibling's Elastic calls fault (O5) without refusing it, while the manifest's recorded
    configured_patterns still guard the staged key set."""
    shim = S.DockerShim(tmp_path / "docker")
    monkeypatch.setenv("PATH", shim.path_value())
    for name in _CONFIG_VARS:
        monkeypatch.delenv(name, raising=False)
    _base, src = H.tenant_source(data_root, TID)
    root = tmp_path / "tenants"
    folder = S.plant(root, TID, marker="mf17")
    manifest = H.family_for(src, tmp_path / "episodes" / T.EPISODE_ID)
    # At the launcher's O9 check the Elastic part was whole ...
    assert isinstance(_resolve(root).elastic, S.record_type("ElasticSettings")), \
        "the tenant's Elastic part was not whole at launch"
    # ... and is edited bad before the sibling starts.
    S.drop_key(folder, "elastic", "ELASTIC_ES_CONTAINER")

    rec = S.RunRecorder(tmp_path / "sibling-run")
    rc, refused = S.drive_run(
        H.resume_argv(manifest, "b", "--tenant", TID, "--tenants-root", str(root)), rec,
        visualize=rec.visualize)

    assert refused is None, f"the sibling was refused: {H.refusal_text(refused)!r}"
    assert rc == 0, f"the sibling exited {rc} ({rec.order})"
    assert len(rec.lifecycle_calls) == 1, f"lifecycle ran {len(rec.lifecycle_calls)} times"
    record, world = rec.lifecycle_calls[0]["tenant"], rec.lifecycle_calls[0]["world"]
    assert isinstance(record.elastic, S.config_fault()), \
        f"the sibling's own record does not see the edit: {record.elastic!r}"
    # Its Elastic calls fault (O5) ...
    run_dir = tmp_path / "sibling-run"
    with pytest.raises(S.config_fault()):
        elastic_adapter.query(S.verb_context(record, run_dir, shim.env()), native_query="*")
    assert shim.calls() == [], f"a faulted Elastic call reached docker: {shim.calls()}"
    # ... while the manifest's recorded patterns still guard the staged key set.
    assert tuple(world.family.configured_patterns) == T.CONFIGURED, \
        f"the sibling's family patterns are not the manifest's: {world.family.configured_patterns}"
    own = confinement.world_view(T.EVENTS_PATTERN, world.world_id)
    registry.refuse_a_foreign_world_view(
        world, "elastic", "query", {"index": own, "native_query": "*"},
        S.verb_context(record, run_dir, shim.env()))


# ---------------------------------------------------------------------------------------------
# CX22 — the foreign-view fallback and the review's contexts read the episode tenant's record.
# ---------------------------------------------------------------------------------------------

def test_c_foreign_view_review_record(tmp_path, data_root, monkeypatch):
    """For a world with no manifest record, the foreign-view guard's fallback patterns come from the
    serving VerbContext's record.elastic. The review's replay verb contexts carry the episode
    tenant's record."""
    for name in _CONFIG_VARS:
        monkeypatch.delenv(name, raising=False)
    root = tmp_path / "tenants"
    S.plant(root, TID, marker="cfv")
    record = _resolve(root)
    episode_dir = T.episode(tmp_path, root=tmp_path / "episodes")
    runs_base = H.runs_dir(data_root, TID)

    # The review's replay contexts: the launcher's read side, and the review's own builder.
    read_side = branch_seams.adapter_seam(episode_dir, record, runs_base=runs_base)
    # G21: a @model keeps a stdlib-dataclass field by identity.
    assert S.record_on(read_side.ctx) is record, "the review's read-side ctx lacks the record"
    replay_ctx = S.review_verb_context(episode_dir, record, runs_base=runs_base)
    assert S.record_on(replay_ctx) is record, "review.verb_context's ctx lacks the record"

    # A world with no manifest record: its fallback patterns are the record's elastic ones.
    world = SimpleNamespace(world_id="fvb", touches=("elastic",),
                            family=SimpleNamespace(configured_patterns=()))
    own = confinement.world_view("cfv-events-*", "fvb")
    registry.refuse_a_foreign_world_view(
        world, "elastic", "query", {"index": own, "native_query": "*"}, read_side.ctx)
    foreign = confinement.world_view("other-events-*", "fvb")
    with pytest.raises(confinement.ConfinementFault):
        registry.refuse_a_foreign_world_view(
            world, "elastic", "query", {"index": foreign, "native_query": "*"}, read_side.ctx)
