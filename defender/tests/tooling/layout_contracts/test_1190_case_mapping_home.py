"""The case-mapping reader (`runtime/case_ticket.py`): file states, wrong shapes, run-start read.
Goldens: `goldens/tenants.json`."""
from __future__ import annotations

from defender.tests.support.shared._locations_1210 import fixture_data_root

import importlib
import os
import textwrap
from pathlib import Path
from typing import Any

import pytest

from defender.tests.support.shared.contracts._data_root_1078 import D9_TENANT_ID
from defender.tests.tooling.layout_contracts import _spec1080 as S
from defender.tests.tooling.layout_contracts.test_1080_writeback_tenants_and_views import (
    _golden,
    _norm,
    _outcome_of,
)
from defender.tests.tenancy.tenant_1107_settings import _spec1107 as T7

#: Every planted tenant's marker (its config values carry it) and its id (the D9 tenant). The
#: goldens were captured with exactly these.
MARKER = "t1080"

TENANT = D9_TENANT_ID


def _case_module() -> Any:
    """The case-mapping module: the one module under `defender/runtime/` defining
    `load_case_mapping` (the base module under `SPEC1080_AT_BASE`)."""
    return S.moved_module("load_case_mapping", home=S.RUNTIME)


def _moved(name: str) -> Any:
    """A case-mapping name from its home under `defender/runtime/`."""
    return S.moved(name, home=S.RUNTIME)


def _writer_home() -> str:
    """The write-back module's path, wherever it lives: `record_case_ticket`'s one home outside
    `defender/scripts/` once #1165 has moved it (the locator's one-home rule decides), else its
    one definition under `scripts/` — `runtime/ticket_writer.py`, which #1190 leaves in
    place. Decided by the definitions, never by catching the locator's failure (that would also
    swallow a duplicate home)."""
    defs = S.definitions("record_case_ticket")
    if any(not S.under(d, "defender/scripts") for d in defs):
        return S.home_of("record_case_ticket")
    assert len(defs) == 1, f"`record_case_ticket` has {len(defs)} definitions: {list(defs)}"
    return defs[0]


def _writer() -> Any:
    """The write-back module, imported by its dotted name."""
    return importlib.import_module(S.dotted(_writer_home()))


MAPPING = textwrap.dedent("""\
    open:
      key: "{case_id}"
      summary: "{summary}"
      description: "Opened from alert {case_id} (rule {signature})."
      status: open
      reporter: defender
      labels:
        - "sig:{signature}"
        - "evt:{event_time}"
    comment:
      author: defender-1080
      body: "[{signature}] {disposition} — {cause}\\n\\n{narrative}"
    released:
      status: closed
    """)

MAPPING_REFUSED = MAPPING.replace("  status: open\n", '  status: "{signature}"\n')

def report_text(disposition: str = "benign",
                cause: str = "the disposition was recorded without a challenge review",
                body: str = "Disposition recorded by the close gate. outcome=stands.") -> str:
    """`report.md` as the close gate writes it (YAML frontmatter; `_triplet_947.report_text`'s
    shape). `cause` is spelled verbatim into the frontmatter, so a caller quotes it if needed."""
    return (f"---\ndisposition: {disposition}\noutcome: stands\ncause: {cause}\n---\n{body}\n")


def _tenant(mapping: str | bytes | None = MAPPING) -> tuple[Path, Path]:
    """The D9 tenant set up under THIS test's data root (`DEFENDER_DATA_ROOT`), its knowledge
    replaced by a complete #1107 tenant (`_spec1107.plant`), its mapping file `mapping` when
    given. Returns (data root, knowledge folder)."""
    from defender.tests.support.shared.contracts._data_root_1078 import current_data_root, ensure_d9_tenant

    ensure_d9_tenant()
    root = current_data_root()
    folder = T7.plant(root, marker=MARKER)
    if mapping is not None:
        path = T7.mapping_path(folder)
        if isinstance(mapping, bytes):
            path.write_bytes(mapping)
        else:
            path.write_text(mapping, encoding="utf-8")
    return root, folder


def _record(root: Path) -> Any:
    """The run's record, resolved the way run start resolves it (`run_tenant.resolve_tenant`,
    unmoved)."""
    from defender.runtime import run_tenant

    return run_tenant.resolve_tenant(fixture_data_root(root), TENANT, defender_dir=S.DEFENDER,
                                     dispatches_lead_zero=False)


def _held(mapping: Any) -> dict[str, Any]:
    """What a record holds as its `ticket_mapping`: the mapping's content, or the kept error."""
    if isinstance(mapping, BaseException):
        return {"error": type(mapping).__name__, "message": str(mapping)}
    return {"mapping": S.canon(mapping.plain())}


def _plain(mapping: Any) -> Any:
    return S.canon(mapping.plain())


def _records_at_run_start() -> tuple[Any, Any]:
    """The run's record over a planted tenant, then again after its mapping is made one the
    loader refuses (a templated open.status): (good, bad)."""
    root, folder = _tenant()
    good = _record(root)
    T7.mapping_path(folder).write_text(MAPPING_REFUSED, encoding="utf-8")
    return good, _record(root)


def _view_at_run_start(good: Any, bad: Any, tmp: Path) -> dict[str, Any]:
    """The record's mapping, as held. (The release predicate the ticket writer built from it was
    observed here too, until #1221's amendment removed it; nothing reads a released status.)"""
    return _norm({
        "record_good": _held(good.ticket_mapping),
        "record_bad": _held(bad.ticket_mapping),
    }, tmp)


def test_1080_the_case_mapping_is_read_at_run_start_from_the_tenants_home(tmp_path):
    home = _case_module()
    case_mapping, case_error = _moved("CaseMapping"), _moved("CaseTicketError")
    assert {case_mapping.__module__, case_error.__module__} == {
        home.__name__}, "the case-mapping types are not all defined in the tenants home"

    good, bad = _records_at_run_start()
    assert isinstance(good.ticket_mapping, case_mapping), (
        f"the record holds {type(good.ticket_mapping)!r}, not the tenants home's CaseMapping")
    assert isinstance(bad.ticket_mapping, case_error), (
        f"a refused mapping is held as {type(bad.ticket_mapping)!r}, not the moved "
        "CaseTicketError")

    assert _view_at_run_start(good, bad, tmp_path) == _golden(
        "s_case_mapping_read_at_run_start")


_LARGE = 1 << 20  # `tenant_settings.SETTINGS_MAX_BYTES` at the base


def _pad_to(text: str, size: int) -> bytes:
    """`text` followed by one YAML comment line making the file exactly `size` bytes."""
    head = text.encode("utf-8")
    filler = size - len(head) - 3
    return head + b"# " + b"x" * filler + b"\n"


#: Each file state, as the bytes put at the mapping's path. `None` content means the state is
#: set up by hand in `_put_state` (`outside` is a folder beyond the tenant's).
FILE_STATES: dict[str, Any] = {
    "absent": None,
    "empty": b"",
    "whitespace_only": b"  \n\t \n\n",
    "bom_prefixed": b"\xef\xbb\xbf" + MAPPING.encode("utf-8"),
    "non_utf8": MAPPING.replace("defender-1080", "défense").encode("latin-1", "replace"),
    "at_the_bound": _pad_to(MAPPING, _LARGE),
    "one_byte_over": _pad_to(MAPPING, _LARGE + 1),
    "symlink_out_of_the_tenant_folder": None,
    "directory": None,
    "fifo": None,
}


def _put_state(path: Path, state: str, outside: Path) -> None:
    path.unlink(missing_ok=True)
    content = FILE_STATES[state]
    if content is not None:
        path.write_bytes(content)
    elif state == "symlink_out_of_the_tenant_folder":
        outside.mkdir(parents=True, exist_ok=True)
        target = outside / "mapping.yaml"
        target.write_text(MAPPING, encoding="utf-8")
        path.symlink_to(target)
    elif state == "directory":
        path.mkdir()
    elif state == "fifo":
        os.mkfifo(path)


def _observe_mapping_file(state: str, tmp: Path, mp: Any) -> dict[str, Any]:
    load = _moved("load_case_mapping")
    root, folder = _tenant()
    _put_state(T7.mapping_path(folder), state, tmp / "outside")
    loaded = _outcome_of(load, T7.settings_of(folder), view=_plain)
    try:
        held: Any = _held(_record(root).ticket_mapping)
    except Exception as e:  # noqa: BLE001 — a refusal at run start is the observed outcome
        held = {"refused": type(e).__name__, "message": str(e)}
    return _norm({"load_case_mapping": loaded, "held_on_run_tenant": held}, tmp)


@pytest.mark.parametrize("state", list(FILE_STATES))
def test_case_mapping_file_in_each_state(state, tmp_path):
    assert _observe_mapping_file(state, tmp_path, None) == _golden("s187")[state]


#: YAML documents of the wrong shape (each a complete file).
YAML_SHAPES: dict[str, str] = {
    "list": "- source\n- open\n",
    "scalar": "just a sentence\n",
    "null_tilde": "~\n",
    "null_word": "null\n",
    "comment_only": "# nothing here\n",
    "duplicate_top_level_key": MAPPING + "comment:\n  author: someone-else\n  body: \"{case_id}\"\n",
    "duplicate_nested_key": MAPPING.replace("  status: closed\n",
                                            "  status: closed\n  status: open\n"),
    "unknown_keys": MAPPING + "escalate:\n  to: nobody\nextra: 1\n",
    "open_status_an_integer": MAPPING.replace("  status: open\n", "  status: 42\n"),
    "open_status_a_template": MAPPING.replace("  status: open\n", "  status: \"{signature}\"\n"),
    "released_a_scalar": MAPPING.replace("released:\n  status: closed\n", "released: closed\n"),
    "comment_author_a_list": MAPPING.replace("  author: defender-1080\n",
                                             "  author: [a, b]\n"),
    "comment_missing": MAPPING.replace(
        "comment:\n  author: defender-1080\n"
        "  body: \"[{signature}] {disposition} — {cause}\\n\\n{narrative}\"\n", ""),
    "anchor_and_alias": MAPPING.replace("open:\n", "base: &b {status: open}\nopen:\n")
    .replace("released:\n  status: closed\n", "released: *b\n"),
    "merge_key": MAPPING.replace("open:\n", "base: &b {reporter: defender}\nopen:\n  <<: *b\n"),
    "python_object_tag": MAPPING + "hook: !!python/object/apply:os.getcwd []\n",
    "python_name_tag": MAPPING + "hook: !!python/name:os.system\n",
    "invalid_yaml": "open: [unclosed\n",
    "tab_indented": "open:\n\tstatus: open\n",
    "two_documents": MAPPING + "---\nsecond: doc\n",
}


def _observe_yaml_shape(shape: str, tmp: Path, mp: Any) -> dict[str, Any]:
    load = _moved("load_case_mapping")
    settings = tmp / "settings"
    path = settings / "systems" / "case-history" / "mapping.yaml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(YAML_SHAPES[shape], encoding="utf-8")
    return _norm({"load_case_mapping": _outcome_of(load, settings, view=_plain)}, tmp)


@pytest.mark.parametrize("shape", list(YAML_SHAPES))
def test_case_mapping_yaml_of_the_wrong_shape(shape, tmp_path):
    assert _observe_yaml_shape(shape, tmp_path, None) == _golden("s188")[shape]
