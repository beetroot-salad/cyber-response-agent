"""Shared machinery for #1107's spec — "the tenant settings record". NO test scripts.

The change (`spec-flow/specs/spec_graph_1107.yaml`, `.spec-flow/frontiers/70-resolutions.md`):
`RunTenant` grows four fields built once at resolve (`systems`, `elastic`, `ticket_mapping`,
`secrets`); every settings reader moves behind them; no tenant setting is taken from the process
environment any more; each system names its access method (`<PREFIX>_TRANSPORT=docker-exec`,
`<PREFIX>_DOCKER_CONTEXT`, no default); secrets are `*_SECRET_REF` references into a per-tenant,
git-ignored `settings/secrets.env`, read per lookup and delivered only into one child's
environment; a failed ticket write leaves an error receipt the run page shows.

NONE OF THE NEW NAMES EXISTS AT BASE dafb2da3. Every new symbol is reached at CALL time — as an
attribute of a module that already exists (`run_tenant.SystemConfig`), or through `mod()` — so a
missing name is ONE failure per test, never a collection error that hides every other assertion.

COINED NAMES LIVE HERE AND NOWHERE ELSE. The design (and §7 F0, human) names the record's four
fields, the four record types and their home (`runtime.run_tenant`), `VerbContext`'s field
(`tenant`, in place of `settings_dir`), `ElasticSettings`' attributes, `secrets.get(name)`, the
receipt shape and the lint's `main(argv) -> int`. It does NOT name:

  * the keyword the ticket writer's two steps take the record, the defender dir and the run env
    under (`tenant=`, `defender_dir=`, `env=` here — `record_step` / `open_step`);
  * the keyword the `case_ticket` mapping consumers take the mapping under (`mapping=` here —
    `with_mapping`), nor `release_predicate`'s (positional here — `released_status`);
  * the keyword a transport call names the secrets its one child needs under (`secrets=`, a tuple
    of declared names, here — `SECRETS_KW`);
  * how the run page learns `--update-ticket` (PG-2a: run.py passes it as an ARGUMENT; the
    renderer's keyword is `update_ticket=` here — `render_page`);
  * how the env lint is pointed at a planted tree (`main(["--root", <tree>])` here — `run_env_lint`),
    nor its inline suppression token (`ENV_LINT_SUPPRESSION`, spelled like the repo's other
    lints' `# lint-monkeypatch: ok`, asserted ABSENT from every swept file);
  * the keyword the replay helper chain stops taking (`grants=` — `GRANTS_KW`) and the retired
    field / parameter the record replaces (`settings_dir` — `RETIRED_FIELD`).

If write-code-from-spec spells any of these differently, it renames it HERE, never through a
`conceptAliases` entry (which would silently disable `check_binds`' prose scan for the concept).

FAULTS ARE REAL INPUTS THROUGH THE REAL PRIMITIVE wherever the primitive is cheap: the deleted
`config.env`, the non-UTF-8 bytes, the symlinked `secrets.env`, the FIFO, the planted receipt, the
exported config-key variable are written to (or set in) the real filesystem / process env in the
test itself. The one dependency too expensive to drive is the docker CLI, and it is faked the way
CX8 (executed) says it can be without a seam or a monkeypatch: a `docker` executable first on the
PATH of the environment the transport forks with (`DockerShim`). The shim RECORDS what it received
(argv and the child's whole environment, a secret-looking value it inherited from the test
runner redacted) and ANSWERS from a data spec; it classifies nothing. Its
fault content cites its claim at each use: an unknown context's `context not found` (G23, RG3), an
HTTP body/status line in curl's `-w '\\n%{http_code}'` shape (the transport's own contract).

Underscore-prefixed so pytest does not collect it; it defines no tests.
"""
from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import re
import sys
import uuid
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

from defender.tests import _tenants1106 as T1106
from defender.tests._by_path import LINT_DIR, load_module

REPO_ROOT = T1106.REPO_ROOT
DEFENDER = T1106.DEFENDER
PLAYGROUND_ID = T1106.PLAYGROUND_ID
FIXTURE = T1106.FIXTURE
TEMPLATE_DIR = T1106.TEMPLATE_DIR

mod = T1106.mod

# ======================================================================================
# Coined names (see the module docstring) — one edit each if the implementation differs.
# ======================================================================================

#: The field `VerbContext` and `AgentDeps` carry the record under (§7 F0, human: "a field named
#: tenant in place of settings_dir").
RECORD_FIELD = "tenant"
#: The keyword a transport call names the secrets its one child needs under (coined).
SECRETS_KW = "secrets"
#: The reference-key suffix (F10, auto: stays `_SECRET_REF`).
SECRET_REF_SUFFIX = "_SECRET_REF"
#: The one implemented access method (D2).
DOCKER_EXEC = "docker-exec"
#: The per-tenant secret store's file name, under `settings/` (D3).
SECRETS_ENV = "secrets.env"
#: The new lint's program name (O7).
ENV_LINT = "lint_tenant_env_reads"
#: The two cause phrases O9 / F11 name (demand text, verbatim).
NO_ELASTIC = "no elastic system configured"
BAD_ELASTIC = "elastic config is bad"
#: The page's ticket-line word for a receipt it will not trust (NF-26, demand text).
RECEIPT_UNREADABLE = "receipt unreadable"
#: The fault text a system with no folder raises, at base and after (CX5).
NOT_CONFIGURED = "this tenant's settings do not configure this system"
#: The parameter / field the record replaces (design: `settings_dir` retires from `VerbContext`,
#: `AgentDeps` and every function taking `settings_dir=`, G8/CX12).
RETIRED_FIELD = "settings_dir"
#: The keyword the replay helper chain stops taking (d_grants_through_tenant_config).
GRANTS_KW = "grants"
#: `ElasticSettings`' seven attributes (§7 F0, human) — compared as one vector, since the design
#: does not say whether the type defines equality.
ELASTIC_ATTRS: tuple[str, ...] = (
    "events_index", "alerts_index", "url", "ssl_verify", "es_container", "kibana_container",
    "docker_context")
#: The env lint's inline suppression token, in either spelling (coined; the repo's other lints
#: spell theirs `# lint-monkeypatch: ok — <reason>`). o7_lint_clean_empty_allowlist asserts no
#: swept file carries it.
ENV_LINT_SUPPRESSION = re.compile(r"lint[-_]tenant[-_]env[-_]reads\s*:", re.I)
#: The config-shaped variables a developer's shell might carry, cleared before a branch launch so
#: a value either side of an assertion is the one the test put there.
BRANCH_CONFIG_VARS: tuple[str, ...] = (
    "ELASTIC_EVENTS_INDEX", "ELASTIC_ALERTS_INDEX", "ELASTICSEARCH_URL", "ELASTIC_SSL_VERIFY",
    "SOC_PLAYGROUND_ES_CONTAINER", "SOC_PLAYGROUND_KIBANA_CONTAINER",
    "SOC_PLAYGROUND_DOCKER_CONTEXT", "CMDB_URL_BASE", "DEFENDER_RUN_DIR", "DEFENDER_RUNS_BASE")


def run_tenant_mod() -> Any:
    """`defender.runtime.run_tenant` — the record's module (d1096: the four types live here)."""
    return mod("runtime.run_tenant")


def record_type(name: str) -> type:
    """One of `SystemConfig`, `ElasticSettings`, `CaseMapping`, `SecretLookup` — asserted to BE a
    class the record's module defines (d1096), so a test that asks where a type lives, or
    whether a value is one, can never read an absent or stand-in name as an answer."""
    cls = getattr(run_tenant_mod(), name, None)
    assert isinstance(cls, type), f"runtime.run_tenant does not define the record type {name}: {cls!r}"
    return cls


def config_fault() -> type:
    """`ConfigFault` — the adapters' own class, exit 2 (CX5)."""
    return mod("scripts.adapters.faults").ConfigFault


def case_ticket_error() -> type:
    return mod("runtime.case_ticket").CaseTicketError


def tenant_refused() -> type:
    return mod("_tenant").TenantRefused


def settings_pointer() -> str:
    """`SETTINGS_POINTER` — the model-facing name of the tenant's settings folder (#1106)."""
    return mod("runtime.verbs").SETTINGS_POINTER


# ======================================================================================
# Fixture tenants. Every value carries a marker, so a reader that returns another tenant's (or
# the checkout's, or the environment's) value is caught by the value alone.
# ======================================================================================

#: Each system folder's key prefix, as the adapters spell it.
PREFIX: dict[str, str] = {
    "cmdb": "CMDB",
    "identity": "IDENTITY",
    "ticket": "TICKET",
    "case-history": "CASE_HISTORY",
    "change-mgmt": "CHANGE_MGMT",
    "threat-intel": "THREAT_INTEL",
    "elastic": "ELASTIC",
    "host-state": "HOST_STATE",
}

#: The six docker-exec-curl stub systems (`_stub_transport.load_config`'s three-key template).
STUB_SYSTEMS: tuple[str, ...] = (
    "cmdb", "identity", "ticket", "case-history", "change-mgmt", "threat-intel")

#: The keys `ElasticSettings` is all-or-nothing over (d_elastic_view, MF-7 a/b), beside
#: `ELASTIC_TRANSPORT`, which must equal `docker-exec`.
ELASTIC_VIEW_KEYS: tuple[str, ...] = (
    "ELASTIC_EVENTS_INDEX", "ELASTIC_ALERTS_INDEX", "ELASTICSEARCH_URL", "ELASTIC_SSL_VERIFY",
    "ELASTIC_ES_CONTAINER", "ELASTIC_KIBANA_CONTAINER", "ELASTIC_DOCKER_CONTEXT")


def context_name(marker: str, system: str) -> str:
    """The docker context a fixture tenant names for `system` — distinct per system and per
    tenant, and never `soc-playground` (the base's built-in default, CX17)."""
    return f"ctx-{marker}-{system}"


def es_container(marker: str) -> str:
    return f"es-{marker}"


def kibana_container(marker: str) -> str:
    return f"kibana-{marker}"


def config_texts(marker: str, *, events_index: str | None = None,
                 alerts_index: str | None = None) -> dict[str, str]:
    """One COMPLETE post-#1107 `config.env` per system, host-state's new one included.

    `_tenants1106.config_texts` plus what D2 adds: every system's `<PREFIX>_TRANSPORT` and
    `<PREFIX>_DOCKER_CONTEXT`, elastic's two containers, and the two stub systems it omits
    (change-mgmt, threat-intel). A fixture without these lines is a tenant whose every system is
    down once #1107 lands (no default), so a scenario about one fault would ride on eight."""
    base = T1106.config_texts(marker, events_index=events_index, alerts_index=alerts_index)
    base["change-mgmt"] = (
        f'CHANGE_MGMT_URL_BASE="http://change-mgmt-{marker}:8080"\n'
        f'CHANGE_MGMT_BASTION_HOST="bastion-{marker}"\n'
        'CHANGE_MGMT_TIMEOUT_SEC="10"\n')
    base["threat-intel"] = (
        f'THREAT_INTEL_URL_BASE="http://threat-intel-{marker}:8080"\n'
        f'THREAT_INTEL_BASTION_HOST="bastion-{marker}"\n'
        'THREAT_INTEL_TIMEOUT_SEC="10"\n')
    base["host-state"] = ""
    out: dict[str, str] = {}
    for system, text in base.items():
        prefix = PREFIX[system]
        text += (f'{prefix}_TRANSPORT="{DOCKER_EXEC}"\n'
                 f'{prefix}_DOCKER_CONTEXT="{context_name(marker, system)}"\n')
        if system == "elastic":
            text += (f'ELASTIC_ES_CONTAINER="{es_container(marker)}"\n'
                     f'ELASTIC_KIBANA_CONTAINER="{kibana_container(marker)}"\n')
        out[system] = text
    return out


def plant(root: Path, tenant_id: str = PLAYGROUND_ID, *, marker: str = "t1107",
          configs: dict[str, str] | None = None, secrets: str | Mapping[str, str] | None = None,
          table: str = T1106.TABLE_A, **kw: Any) -> Path:
    """Set a complete #1107 tenant up under the data root `root` and return its knowledge
    folder `root/<tenant_id>/knowledge/` (#1120: the settings half is `<folder>/settings`).

    A knowledge folder already there (`_spec1078.tenant_source` places the committed fixture's)
    is replaced whole, so every value the tenant carries is this call's. `configs` replaces the
    per-system `config.env` set (default `config_texts(marker)`); `secrets` writes
    `settings/secrets.env` (a mapping is rendered `KEY="value"` per line). The rest (`table`,
    `omit`, `lead_zero`, …) is `_tenants1106.plant_tenant`'s."""
    import shutil

    shutil.rmtree(Path(root) / tenant_id / "knowledge", ignore_errors=True)
    folder = T1106.place_tenant(
        root, tenant_id, table=table,
        configs=configs if configs is not None else config_texts(marker), **kw)
    if secrets is not None:
        write_secrets(folder, secrets)
    return folder


def settings_of(folder: Path) -> Path:
    return Path(folder) / "settings"


def config_path(folder: Path, system: str) -> Path:
    return settings_of(folder) / "systems" / system / "config.env"


def secrets_path(folder: Path) -> Path:
    return settings_of(folder) / SECRETS_ENV


def mapping_path(folder: Path) -> Path:
    return settings_of(folder) / "systems" / "case-history" / "mapping.yaml"


def write_config(folder: Path, system: str, text: str | bytes) -> Path:
    path = config_path(folder, system)
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(text, bytes):
        path.write_bytes(text)
    else:
        path.write_text(text, encoding="utf-8")
    return path


def set_key(folder: Path, system: str, key: str, value: str) -> Path:
    """Set `key="value"` in `system`'s `config.env` — replacing its line, or appending one."""
    path = config_path(folder, system)
    lines = path.read_text(encoding="utf-8").splitlines() if path.is_file() else []
    kept = [ln for ln in lines if ln.split("=", 1)[0].strip() != key]
    kept.append(f'{key}="{value}"')
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(kept) + "\n", encoding="utf-8")
    return path


def drop_key(folder: Path, system: str, key: str) -> Path:
    """Remove every `key=` line from `system`'s `config.env`."""
    path = config_path(folder, system)
    lines = path.read_text(encoding="utf-8").splitlines()
    path.write_text(
        "\n".join(ln for ln in lines if ln.split("=", 1)[0].strip() != key) + "\n",
        encoding="utf-8")
    return path


def render_env(entries: str | Mapping[str, str]) -> str:
    if isinstance(entries, str):
        return entries
    return "".join(f'{k}="{v}"\n' for k, v in entries.items())


def write_secrets(folder: Path, entries: str | bytes | Mapping[str, str]) -> Path:
    """Write `settings/secrets.env` — a real file, by replace (write then rename), the way D3's
    guide tells an operator to rotate one (NF-12)."""
    path = secrets_path(folder)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{SECRETS_ENV}.{uuid.uuid4().hex}")
    if isinstance(entries, bytes):
        tmp.write_bytes(entries)
    else:
        tmp.write_text(render_env(entries), encoding="utf-8")
    os.replace(tmp, path)
    return path


def resolve(root: Path, tenant_id: str = PLAYGROUND_ID, *, dispatches_lead_zero: bool = False,
            **kw: Any) -> Any:
    """`run_tenant.resolve_tenant` over a planted root — the one acceptance frame. A test about
    the resolver itself calls `run_tenant.resolve_tenant` in its own body; this is for the ones
    that need a record to drive something else."""
    return run_tenant_mod().resolve_tenant(
        Path(root), tenant_id, defender_dir=DEFENDER,
        dispatches_lead_zero=dispatches_lead_zero, **kw)


def tenant_folder_of(root: Path, tenant_id: str = PLAYGROUND_ID) -> Any:
    """The accepted `Tenant` for a planted tenant (the replay harness's `tenant=` input)."""
    return T1106.accept(Path(root), tenant_id)


def _require_data_root(root: Path) -> None:
    """#1120: an entry point reads its tenants from `DEFENDER_DATA_ROOT` alone (there is no
    tenants-root flag), so a test drives one over a tenant planted under THIS test's data root."""
    from defender.tests import _data_root_1078

    here = _data_root_1078.current_data_root()
    assert Path(root).resolve() == here.resolve(), (
        f"{root} is not this test's data root ({here}): plant the tenant under the data root")


# ======================================================================================
# Verb contexts.
# ======================================================================================

def verb_context(record: Any, run_dir: Path, env: Mapping[str, str], **kw: Any) -> Any:
    """A `VerbContext` carrying `record` in its `tenant` field (F0), with no `settings_dir`."""
    fields = {"defender_dir": DEFENDER, "run_dir": Path(run_dir), "env": env,
              RECORD_FIELD: record}
    fields.update(kw)
    return mod("runtime.verbs").VerbContext(**fields)


def record_on(ctx: Any) -> Any:
    """The record a context carries (F0's field)."""
    return getattr(ctx, RECORD_FIELD)


def launch_branch(src: Path, data_root: Path, **seams: Any) -> tuple[Any, BaseException | None]:
    """The REAL branch launcher (`learning.branch.cli.main`) over the source run `src`, whose
    tenant is planted under `data_root` (this test's), every seam faked (`_triplet_947`'s fakes,
    no role preflight) unless handed in. Returns `(rc, None)` or `(None, the SystemExit it
    refused with)`."""
    _require_data_root(data_root)
    from defender.tests import _triplet_947 as t947
    from defender.tests.tenant_1078_pass_a import _spec1078 as h1078

    fakes: dict[str, Any] = {
        "spawn": t947.FakeSpawn(), "questioner": t947.FakeAgent(),
        "live_tree": t947.source_capture(), "preflight": t947.no_preflight}
    fakes.update(seams)
    argv = [str(src), str(t947.BRANCH_MESSAGE_ID), "--continuation-prompt",
            h1078.CONTINUATION]
    try:
        return mod("learning.branch.cli").main(argv, **fakes), None
    except SystemExit as refused:
        return None, refused


def with_mapping(fn: Any, *args: Any, mapping: Any, **kw: Any) -> Any:
    """Call one `case_ticket` mapping consumer with the record's mapping under the coined
    `mapping=` keyword (the design says only "take the mapping instead of settings_dir")."""
    return fn(*args, mapping=mapping, **kw)


def released_status(mapping: Any) -> str:
    """`case_ticket.release_predicate` over a record's `ticket_mapping`, handed POSITIONALLY
    (coined), and the `released.status` it keys on."""
    return mod("runtime.case_ticket").release_predicate(mapping).released_status


# ======================================================================================
# The docker CLI, faked on PATH (CX8, executed): `subprocess.run(..., env=E)` resolves
# `docker` on E's PATH, so a shim there receives the transport's argv and the child's whole
# environment. No runner seam, no monkeypatch (F5, auto).
# ======================================================================================

#: Secret-looking variables this process INHERITED (name -> sha256 of its value), snapshotted at
#: import, before any test plants its own. The shim logs such a variable's value as
#: `INHERITED_REDACTED` when it still equals the inherited one, so a real token on the box running
#: the suite never lands in a test's call log; a value a test planted never matches, and the
#: variable's NAME is still logged (a scrub test asks whether the name reached the child).
_SECRETISH = re.compile(r"(?i)(KEY|TOKEN|SECRET|PASSW|CREDENTIAL|AUTH)")
_INHERITED_SECRETS: dict[str, str] = {
    k: hashlib.sha256(v.encode("utf-8", "surrogateescape")).hexdigest()
    for k, v in os.environ.items() if _SECRETISH.search(k)}
INHERITED_REDACTED = "<redacted: inherited from the test runner>"

_SHIM = r'''
import hashlib, json, os, sys
LOG = {log!r}
SPEC = {spec!r}
INHERITED = {inherited!r}
def _logged(k, v):
    h = INHERITED.get(k)
    if h is not None and hashlib.sha256(v.encode("utf-8", "surrogateescape")).hexdigest() == h:
        return {redacted!r}
    return v
env = {{k: _logged(k, v) for k, v in os.environ.items()}}
with open(LOG, "a", encoding="utf-8") as fh:
    fh.write(json.dumps({{"argv": sys.argv[1:], "env": env}}) + "\n")
with open(LOG, encoding="utf-8") as fh:
    n = sum(1 for _ in fh) - 1
with open(SPEC, encoding="utf-8") as fh:
    spec = json.load(fh)
answers = spec["answers"]
a = answers[min(n, len(answers) - 1)]
out = a.get("stdout", "")
if a.get("status") is not None:
    out = out + "\n" + str(a["status"])
sys.stdout.write(out)
sys.stderr.write(a.get("stderr", ""))
sys.exit(int(a.get("rc", 0)))
'''


def answer(stdout: str = "{}", status: str | None = "200", *, rc: int = 0,
           stderr: str = "") -> dict[str, Any]:
    """One canned `docker` reply. `status` is appended on its own trailing line, curl's
    `-w '\\n%{http_code}'` shape that `split_status` recovers (the transport's own contract);
    `None` emits stdout as-is (a non-curl `docker` call, or a curl that printed nothing)."""
    return {"stdout": stdout, "status": status, "rc": rc, "stderr": stderr}


#: An unknown docker context, as the real client answers it (G23: unknown -> rc 1 'context not
#: found'; RG3: the same for a dash-leading name, taken literally).
def context_not_found(name: str) -> dict[str, Any]:
    return answer("", None, rc=1, stderr=(
        f'unable to resolve docker endpoint: context "{name}": context not found\n'))


# The transport's real failure shapes (AP3, executed — 82-author-probes.md): every transient
# docker-exec / curl failure exits non-zero WITH a short diagnostic stderr, and none of them repeats
# the request or its headers (AP2, refuted: the transport never passes -v/--trace). curl's own
# failures still print the `-w` status line (`"\n000"`); a daemon refusal prints nothing to stdout.

def curl_refused(host: str, port: int = 8080) -> dict[str, Any]:
    """curl could not connect (rc=7)."""
    return answer("", "000", rc=7, stderr=(
        f"curl: (7) Failed to connect to {host} port {port} after 0 ms: "
        "Could not connect to server\n"))


def curl_timed_out(ms: int = 3001) -> dict[str, Any]:
    """curl's `--max-time` expired against a target that accepted and never answered (rc=28)."""
    return answer("", "000", rc=28, stderr=(
        f"curl: (28) Operation timed out after {ms} milliseconds with 0 bytes received"))


def no_such_container(name: str) -> dict[str, Any]:
    """`docker exec` into a container that does not exist (rc=1, the daemon's own text)."""
    return answer("", None, rc=1, stderr=f"Error response from daemon: No such container: {name}")


def container_not_running(container_id: str = "3f2a9c1e7b44") -> dict[str, Any]:
    """`docker exec` into a stopped container (rc=1, the daemon's own text)."""
    return answer("", None, rc=1,
                  stderr=f"Error response from daemon: container {container_id} is not running")


class DockerShim:
    """A `docker` executable in `<root>/fakebin`, recording every call and answering in order
    from `answers` (the last answer repeats). Inject it by putting `path_dir` first on the PATH
    of the environment the transport forks with — a run env (`monkeypatch.setenv("PATH", ...)`
    before run.py builds it) or a `VerbContext.env` the test hands in."""

    def __init__(self, root: Path, answers: Iterable[dict[str, Any]] | None = None) -> None:
        self.root = Path(root)
        self.path_dir = self.root / "fakebin"
        self.log = self.root / "docker-calls.jsonl"
        self.spec = self.root / "docker-spec.json"
        self.path_dir.mkdir(parents=True, exist_ok=True)
        exe = self.path_dir / "docker"
        exe.write_text(f"#!{sys.executable}\n"
                       + _SHIM.format(log=str(self.log), spec=str(self.spec),
                                      inherited=_INHERITED_SECRETS, redacted=INHERITED_REDACTED),
                       encoding="utf-8")
        exe.chmod(0o755)
        self.respond(*(list(answers) if answers is not None else [answer()]))

    def respond(self, *answers: dict[str, Any]) -> DockerShim:
        self.spec.write_text(json.dumps({"answers": list(answers) or [answer()]}),
                             encoding="utf-8")
        return self

    def env(self, base: Mapping[str, str] | None = None, **extra: str) -> dict[str, str]:
        """`base` (default: this process's env) with the shim first on PATH, plus `extra`."""
        env = dict(os.environ if base is None else base)
        env["PATH"] = f"{self.path_dir}{os.pathsep}{env.get('PATH', '')}"
        env.update(extra)
        return env

    def path_value(self) -> str:
        """A PATH value with the shim first — for `monkeypatch.setenv("PATH", ...)`."""
        return f"{self.path_dir}{os.pathsep}{os.environ.get('PATH', '')}"

    def calls(self) -> list[dict[str, Any]]:
        """Every recorded call: `{"argv": [...without "docker"], "env": {...}}`."""
        if not self.log.is_file():
            return []
        return [json.loads(ln) for ln in self.log.read_text(encoding="utf-8").splitlines() if ln]


def context_of(argv: list[str]) -> str | None:
    """The `--context` value a docker argv carries — the next token, or `--context=<v>` (RG3:
    docker reads both shapes as a literal name). `None` when absent."""
    for i, tok in enumerate(argv):
        if tok == "--context" and i + 1 < len(argv):
            return argv[i + 1]
        if tok.startswith("--context="):
            return tok.split("=", 1)[1]
    return None


#: `docker exec` options that take a separate value token (`-e NAME`, `--user u`, ...): the
#: value is never the container. A forwarded secret name (`-e CH_TOKEN`) must not read as one.
_EXEC_VALUE_OPTS = frozenset({"-e", "--env", "--env-file", "-u", "--user", "-w", "--workdir",
                              "--detach-keys"})


def exec_target(argv: list[str]) -> str | None:
    """The container a `docker … exec [options] <container> …` argv targets — options and the
    value tokens of value-taking options (`-e NAME`, `-u user`, `-w dir`) skipped."""
    if "exec" not in argv:
        return None
    rest = argv[argv.index("exec") + 1:]
    while rest and rest[0].startswith("-"):
        opt = rest[0]
        rest = rest[2:] if opt in _EXEC_VALUE_OPTS else rest[1:]
    return rest[0] if rest else None


def curl_url(argv: list[str]) -> str | None:
    """The URL a docker-exec'd curl was pointed at (the transport puts it last)."""
    urls = [a for a in argv if a.startswith(("http://", "https://"))]
    return urls[-1] if urls else None


# ======================================================================================
# run.py main, through its injection seams (the #1078 `Recorder` shape).
# ======================================================================================

def run_py() -> Any:
    return mod("run")


def run_argv(alert: Path, data_root: Path, *, tenant_id: str = PLAYGROUND_ID,
             update_ticket: bool = False, run_id: str | None = None,
             extra: Iterable[str] = ()) -> list[str]:
    """`run.py`'s argv for `tenant_id`, planted under `data_root` (this test's)."""
    _require_data_root(data_root)
    argv = [str(alert), "--tenant", tenant_id]
    if update_ticket:
        argv.append("--update-ticket")
    if run_id is not None:
        argv += ["--run-id", run_id]
    return [*argv, *extra]


def plant_alert(where: Path, *, alert_id: str = "a-1107") -> Path:
    where = Path(where)
    where.mkdir(parents=True, exist_ok=True)
    path = where / "alert.json"
    path.write_text(json.dumps({"alert_id": alert_id, "rule": {"id": "r-1107",
                                                              "description": "spec 1107"},
                                "timestamp": "2026-09-28T00:00:00Z"}), encoding="utf-8")
    return path


class RunRecorder:
    """ONE fake per `run.main` seam, each RECORDING what it was handed — it decides nothing.

    `materialize` builds the run dir where told, with a real (empty) session store behind its
    pointer so the REAL page renderer (`run_common.visualize`, the default `visualize` seam) can
    render it; `lifecycle` returns `summary` (the run-end record the ticket lane reads:
    `truncated_by`, `closed_before_cut`). `visualize` is left to production unless a test asks
    for the recording one (`seams(record_visualize=True)`)."""

    def __init__(self, run_dir_at: Path, *, summary: Mapping[str, Any] | None = None,
                 before_lifecycle: Any = None) -> None:
        self.run_dir_at = Path(run_dir_at)
        self.summary = dict(summary or {"output": "spec1107", "requests": 0,
                                        "truncated_by": None})
        self.before_lifecycle = before_lifecycle
        self.order: list[str] = []
        self.lifecycle_calls: list[dict[str, Any]] = []
        self.visualize_calls: list[tuple[tuple[Any, ...], dict[str, Any]]] = []

    def preflight(self, model: str | None = None, *, branching: bool = False) -> int:
        self.order.append("preflight")
        return 0

    def materialize(self, alert: Path, run_id: str | None, **kw: Any) -> Any:
        self.order.append("materialize")
        run_dir = self.run_dir_at
        run_dir.mkdir(parents=True, exist_ok=True)
        (run_dir / "alert.json").write_bytes(Path(alert).read_bytes())
        seed_session_store(run_dir)
        return mod("run_repository._handle").Run.at(run_dir)

    def lifecycle(self, **kw: Any) -> dict[str, Any]:
        self.order.append("lifecycle")
        self.lifecycle_calls.append(kw)
        if self.before_lifecycle is not None:
            self.before_lifecycle(kw["run_dir"])
        return dict(self.summary)

    def visualize(self, *args: Any, **kw: Any) -> None:
        self.order.append("visualize")
        self.visualize_calls.append((args, kw))

    def enqueue(self, *_a: Any, **_kw: Any) -> bool:
        self.order.append("enqueue")
        return False

    def seams(self, *, record_visualize: bool = False) -> dict[str, Any]:
        s: dict[str, Any] = {"preflight": self.preflight, "materialize": self.materialize,
                             "lifecycle": self.lifecycle, "enqueue": self.enqueue}
        if record_visualize:
            s["visualize"] = self.visualize
        return s


def seed_session_store(run_dir: Path) -> None:
    """A real, empty session store behind the run dir's pointer — `render_and_mirror`'s
    precondition (the page is refused for a run whose record cannot be found)."""
    ss = mod("runtime.session_store")
    store = ss.open_store(case_id=f"c1107-{uuid.uuid4().hex[:12]}", runs_base=Path(run_dir).parent)
    try:
        ss.write_case_pointer(Path(run_dir), case_id=store.case_id, store_path=store.path)
    finally:
        store.close()


def drive_run(argv: list[str], rec: RunRecorder, **seams: Any) -> tuple[int | None, Any]:
    """Drive the REAL `run.main` over `argv` with `rec`'s seams (plus `seams`). Returns
    `(exit status, None)` or `(None, the SystemExit it refused with)`."""
    try:
        return run_py().main(argv, **{**rec.seams(), **seams}), None
    except SystemExit as refused:
        return None, refused


# ======================================================================================
# The ticket writer and its receipt (O6).
# ======================================================================================

def ticket_writer() -> Any:
    return mod("scripts.case_history.ticket_writer")


def record_step(run_dir: Path, record: Any, *, env: Mapping[str, str],
                defender_dir: Path = DEFENDER, **kw: Any) -> Any:
    """`record_case_ticket` as run.py calls it after #1107: the record, the defender dir and the
    run env handed in (coined keywords `tenant=`, `defender_dir=`, `env=`; F6, human)."""
    return ticket_writer().record_case_ticket(
        Path(run_dir), tenant=record, defender_dir=defender_dir, env=dict(env), **kw)


def open_step(run_dir: Path, record: Any, *, env: Mapping[str, str],
              defender_dir: Path = DEFENDER, **kw: Any) -> Any:
    """`open_case_ticket`, same coined keywords as `record_step`."""
    return ticket_writer().open_case_ticket(
        Path(run_dir), tenant=record, defender_dir=defender_dir, env=dict(env), **kw)


def receipt_path(run_dir: Path) -> Path:
    """The receipt: a sidecar beside the run dir, keyed by the run's name, out of the box's reach."""
    return mod("run_repository._layout").RunPaths(Path(run_dir)).ticket_write(Path(run_dir).parent)


def receipt(run_dir: Path) -> dict[str, Any] | None:
    """The receipt as written, or `None` when there is none (a link is not followed)."""
    path = receipt_path(run_dir)
    if path.is_symlink() or not path.is_file():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


#: The shim answers a record step's two calls: the read-back of the case (not released), then
#: the comment POST. Canned in curl's body + status-line shape (the transport's own contract).
def store_answers_ok(key: str) -> list[dict[str, Any]]:
    return [answer(json.dumps({"key": key, "status": "open", "comments": []}), "200"),
            answer(json.dumps({"id": 1}), "201")]


# ======================================================================================
# The run page (O6's page line; NF-26; PG-2/PG-2a).
# ======================================================================================

def render_page(run_dir: Path, *, update_ticket: bool) -> str:
    """Render the page the way run.py does after teardown — `run_common.visualize`, the default
    `visualize` seam — handing it run.py's own `--update-ticket` flag as an ARGUMENT (PG-2a,
    coined keyword `update_ticket=`), and return the page's HTML."""
    mod("run_common").visualize(mod("run_repository._handle").Run.at(Path(run_dir)), update_ticket=update_ticket)
    return page_html(run_dir)


def page_html(run_dir: Path) -> str:
    path = mod("run_repository._layout").RunPaths(Path(run_dir)).runtime_html
    return path.read_text(encoding="utf-8") if path.is_file() else ""


# ======================================================================================
# The env lint (O7) — a program loaded fresh by path, the way CI reaches it.
# ======================================================================================

def env_lint() -> Any:
    """A fresh copy of `scripts/lint/lint_tenant_env_reads.py` — asserted to exist first, so a
    missing lint reads as the demand's own failure, not as a loader crash."""
    path = LINT_DIR / f"{ENV_LINT}.py"
    assert path.is_file(), f"the env lint does not exist: {path}"
    return load_module(path, name=f"{ENV_LINT}_{uuid.uuid4().hex[:8]}")


def run_env_lint(root: Path | None = None) -> tuple[int, str]:
    """Run the lint's `main(argv)` — over the checkout (`root=None`, argv `[]`) or over a planted
    tree laid out like the repo (`--root <tree>`, coined) — and return `(exit, output)`."""
    lint = env_lint()
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = lint.main([] if root is None else ["--root", str(root)])
    return rc, out.getvalue() + err.getvalue()


def plant_module(root: Path, rel: str, text: str) -> Path:
    """Write `text` at `root/rel` (a repo-shaped planted tree), parents included."""
    path = Path(root) / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


# ======================================================================================
# Surfaces a value must not reach (O4, O6, NF-20): read, never judged here.
# ======================================================================================

def files_under(root: Path) -> list[Path]:
    """Every regular file under `root` (links not followed)."""
    out: list[Path] = []
    for cur, _dirs, files in os.walk(root, followlinks=False):
        for name in files:
            p = Path(cur) / name
            if p.is_file() and not p.is_symlink():
                out.append(p)
    return out


def bytes_under(root: Path) -> dict[Path, bytes]:
    return {p: p.read_bytes() for p in files_under(root)}


def holders(root: Path, needle: str) -> list[Path]:
    """The files under `root` whose bytes contain `needle`."""
    b = needle.encode("utf-8")
    return [p for p, data in bytes_under(root).items() if b in data]
