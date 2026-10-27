from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

from defender.tests.tooling.layout_contracts import _spec1080 as S

GOLDEN = "runpage"


def _golden(key: str) -> Any:
    data = S.golden(GOLDEN)
    assert key in data, f"goldens/{GOLDEN}.json has no entry {key!r}"
    return data[key]


def _scrub(value: Any, subs: dict[str, str]) -> Any:
    """`value` (JSON-shaped) with every occurrence of each real path in `subs` replaced by its
    tag (`<TMP>`, `<RUN_DIR>`, ...), longest path first so a nested path is not half-replaced.
    One JSON round trip, so a path inside any string at any depth is caught."""
    text = json.dumps(value, ensure_ascii=False)
    for real, tag in sorted(subs.items(), key=lambda kv: -len(kv[0])):
        text = text.replace(json.dumps(real, ensure_ascii=False)[1:-1], tag)
    return json.loads(text)


_VENV_CHILD = r'''
import importlib.util, os, sys
path, at_call = sys.argv[1], sys.argv[2]
spec = importlib.util.spec_from_file_location("spec1080_venv_copy", path)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
if at_call == "set":
    os.environ["DEFENDER_BOX"] = "1"
else:
    os.environ.pop("DEFENDER_BOX", None)
sys.argv = ["s1080.py"]
mod.reexec_into_venv("s1080.py")
print("RETURNED")
'''


def _observe_venv_knob(tmp: Path) -> dict[str, str]:
    """The moved `reexec_into_venv`, copied to the same repo-relative place under `tmp` beside a
    planted `defender/.venv/bin/python3` that only prints a line: what one call does when
    `DEFENDER_BOX` is unset at import and set at the call, and the reverse."""
    home = S.home_of("reexec_into_venv")
    copy = tmp / home
    copy.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy(S.REPO_ROOT / home, copy)
    fake = tmp / "defender" / ".venv" / "bin" / "python3"
    fake.parent.mkdir(parents=True, exist_ok=True)
    fake.write_text("#!/bin/sh\necho PLANTED-VENV-RAN\n", encoding="utf-8")
    fake.chmod(0o755)
    out = {}
    for label, at_import, at_call in (("unset-at-import-set-at-call", None, "set"),
                                      ("set-at-import-unset-at-call", "1", "unset")):
        env = S.child_env()
        if at_import is not None:
            env["DEFENDER_BOX"] = at_import
        child = S.python("-c", _VENV_CHILD, str(copy), at_call, env=env, cwd=tmp)
        assert child.returncode == 0, child.stderr.decode(errors="replace")
        out[label] = child.stdout.decode().strip()
    return out


def _observe_knobs(tmp: Path, monkeypatch, capsys) -> dict[str, Any]:
    """Each moved module's knob, set or changed AFTER the module was imported, and what the
    module then acts on."""
    out: dict[str, Any] = {}
    pmax = S.moved("passthrough_max_bytes")
    knob = "DEFENDER_GATHER_PASSTHROUGH_MAX_BYTES"
    cap = []
    for value in (None, "100", "0", "not-a-number"):
        if value is None:
            monkeypatch.delenv(knob, raising=False)
        else:
            monkeypatch.setenv(knob, value)
        cap.append(S.outcome(pmax))
    out["payload_passthrough_cap"] = cap

    sql = S.moved_module("EXIT_NO_RUNTIME")
    box = []
    for value in (None, "1"):
        if value is None:
            monkeypatch.delenv("DEFENDER_BOX", raising=False)
        else:
            monkeypatch.setenv("DEFENDER_BOX", value)
        capsys.readouterr()
        rc = sql._no_runtime("duckdb")
        captured = capsys.readouterr()
        box.append({"rc": rc, "stdout": captured.out, "stderr": captured.err})
    monkeypatch.delenv("DEFENDER_BOX", raising=False)
    out["sql_box_marker"] = box

    out["venv_box_marker"] = _observe_venv_knob(tmp / "venv")
    return _scrub(out, {str(tmp): "<TMP>"})


#: s038's knobs the 2026-10-04 scope cut keeps (the moved modules'); the renderer's mirror
#: override (`mirror_override` in the golden) stays in `presentation/`, parked with #1105.
S038_KEPT = ("payload_passthrough_cap", "sql_box_marker", "venv_box_marker")


def test_moved_module_reads_its_environment_knob_at_a_different_point(
        tmp_path, monkeypatch, capsys):
    observed = _observe_knobs(tmp_path, monkeypatch, capsys)
    expected = {k: _golden("s038")[k] for k in S038_KEPT}
    assert observed == expected, (
        "s038: the moved code's behaviour differs from the base's golden\n"
        f"observed: {json.dumps(observed, ensure_ascii=False, indent=1)[:4000]}\n"
        f"golden:   {json.dumps(expected, ensure_ascii=False, indent=1)[:4000]}")


#: (edge, consumer module, a symbol the moved module defines). The consumer's import of that
#: module is at module level, so a stale name is loud at process start.
S053_EDGES = (
    ("api_serve->_venv", "defender.api.serve", "reexec_into_venv"),
    ("tools_init->sql", "defender.investigation.tools", "EXIT_NO_RUNTIME"),
    ("query_tool->payload_view", "defender.investigation.query_tool", "ELISION_PREFIX"),
)

_CLEAN_IMPORTS = r'''
import importlib, json, sys
out = {}
for name in sys.argv[1:]:
    try:
        importlib.import_module(name)
        out[name] = None
    except ImportError as e:
        out[name] = e.name or type(e).__name__
print(json.dumps(out))
'''

_STALE_IMPORT = r'''
import importlib, json, sys
target, consumer = sys.argv[1], sys.argv[2]
sys.modules[target] = None
try:
    importlib.import_module(consumer)
except ImportError as e:
    print(json.dumps({"raised": type(e).__name__, "name": e.name}))
else:
    print(json.dumps({"raised": None}))
'''


def _imports_module(consumer_rel: str, target: str) -> list[S.ImportStmt]:
    """The consumer's MODULE-LEVEL import statements that name `target` (as `from target
    import ...`, `import target`, or `from <package> import <target's last part>`)."""
    src = (S.REPO_ROOT / consumer_rel).read_bytes()
    hits = []
    for st in S.import_statements(consumer_rel, src):
        named = {st.module} | {f"{st.module}.{n}" for n in st.names}
        if target in named and st.top_level:
            hits.append(st)
    return hits


def test_module_level_consumers_of_a_moved_module_meet_a_stale_name_at_import():
    consumers = [c for _edge, c, _sym in S053_EDGES]
    clean = S.python("-c", _CLEAN_IMPORTS, *consumers, cwd="/")
    assert clean.returncode == 0, clean.stderr.decode(errors="replace")
    verdict = json.loads(clean.stdout.decode().splitlines()[-1])
    for consumer, failed in verdict.items():
        assert failed is None or not str(failed).startswith("defender"), (
            f"positive control: {consumer} does not import cleanly ({failed})")

    for edge, consumer, symbol in S053_EDGES:
        target_rel = S.home_of(symbol)
        target = S.dotted(target_rel)
        consumer_rel = consumer.replace(".", "/") + (
            "/__init__.py" if (S.REPO_ROOT / consumer.replace(".", "/")).is_dir() else ".py")
        assert _imports_module(consumer_rel, target), (
            f"{edge}: {consumer_rel} has no module-level import of {target} (where "
            f"`{symbol}` now lives) — a stale or lazy import there would not fail at start")
        stale = S.python("-c", _STALE_IMPORT, target, consumer, cwd="/")
        assert stale.returncode == 0, stale.stderr.decode(errors="replace")
        got = json.loads(stale.stdout.decode().splitlines()[-1])
        assert got["raised"] in ("ImportError", "ModuleNotFoundError"), (
            f"{edge}: importing {consumer} with {target} gone did not fail at import: {got}")
        assert got["name"] == target, f"{edge}: the import failed on another name: {got}"
