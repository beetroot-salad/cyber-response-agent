"""Run and episode identities are canonical UUIDs with no labels or composed meaning."""
from __future__ import annotations

from defender.tests.support.shared._locations_1210 import location_path

import ast
import os
from dataclasses import dataclass
from pathlib import Path

import pytest

from defender.tests.support.shared.contracts import _by_path
from defender.tests.support.learning.branch import _triplet_947 as T947
from defender.tests.storage.ids_1187 import _spec1187 as S
from defender.tests.storage.tenant_1105_run_repository import _spec1105 as H
from defender.tests.storage.tenant_1105_run_repository import _spec1105_pr2 as P

DEFENDER = Path(__file__).resolve().parents[3]


NON_CANONICAL = [pytest.param(text, id=repr(text)) for text in S.NON_CANONICAL_IDS]
# O1 / declared change 2: a minted id is a bare random UUID.

def test_1187_o1_mint_contract():
    import uuid

    from defender.run_repository import RunId

    minted = [RunId.mint() for _ in range(1000)]
    assert all(type(run_id) is RunId for run_id in minted)
    texts = [str(run_id) for run_id in minted]
    assert len(set(texts)) == 1000, "mint repeated an earlier id"
    for run_id, text in zip(minted, texts, strict=True):
        assert S.is_canonical_uuid(text), text
        assert uuid.UUID(text).version == 4, text
        assert RunId.parse(text) == run_id


def test_1187_o1_run_setup_names_a_run_folder_by_a_bare_uuid(tmp_path, data_root):
    from defender import run_common

    t = S.tenant(data_root)
    alert = H.alert_file(tmp_path / "in", "ssh-brute-force.json")

    first = run_common.materialize_run(alert, tenant=t)
    second = run_common.materialize_run(alert, tenant=t)

    runs = Path(location_path(t.runs))
    assert Path(first.run_dir).parent == runs
    assert Path(second.run_dir).parent == runs
    for run in (first, second):
        name = Path(run.run_dir).name
        assert S.is_canonical_uuid(name), f"the minted run folder is named {name!r}"
        assert Path(run.run_dir).is_dir()
    assert Path(first.run_dir).name != Path(second.run_dir).name
# O2 / declared change 1: only canonical lowercase UUID text is an id.

def test_1187_o2_canonical_ids_pass_the_rules():
    from defender.records._run_id import episode_id_fault, run_id_fault

    for text in (S.SAMPLE_UUID, S.new_id()):
        assert run_id_fault(text) is None
        assert episode_id_fault(text) is None


@pytest.mark.parametrize("text", NON_CANONICAL)
@pytest.mark.parametrize("boundary", ["parse", "run_fault", "episode_fault", "run_id", "episode_id"])
def test_1187_o2_noncanonical_ids_are_refused_at_every_boundary(text, boundary):
    from defender.records._run_id import episode_id_fault, run_id_fault
    from defender.run_repository import RunAddress, RunId, RunRefused

    if boundary.endswith("_fault"):
        rule = run_id_fault if boundary == "run_fault" else episode_id_fault
        why = rule(text)
        assert isinstance(why, str), (rule.__name__, text, why)
        assert why, (rule.__name__, text, why)
    elif boundary == "parse":
        assert isinstance(S.raised(RunId.parse, text), RunRefused), text
    else:
        fields = {**_address_fields(), "episode_id": None, boundary: text}
        assert S.raised(RunAddress, **fields) is not None, (boundary, text)


def test_1187_o2_episode_id_rule_asks_for_no_room_for_a_label():
    from defender.records._run_id import episode_id_fault

    why = episode_id_fault("e" * 205)
    assert isinstance(why, str)
    assert "room" not in why, f"the episode id rule still counts room for a label: {why!r}"
    assert episode_id_fault(S.SAMPLE_UUID) is None


def _address_fields() -> dict[str, object]:
    from defender.tenancy import _tenant
    from defender.run_repository import RunId

    return {"tenant_id": _tenant.TenantId(H.T_ID), "run_id": RunId.parse(S.SAMPLE_UUID)}


def test_1187_o2_run_address_admits_canonical_uuid_run_and_episode_ids():
    from defender.run_repository import RunAddress

    ep = S.new_id()
    arm = RunAddress(tenant_id=_address_fields()["tenant_id"], run_id=S.new_id(), episode_id=ep)
    assert arm.episode_id == ep
    assert S.is_canonical_uuid(str(arm.run_id))
    natural = RunAddress(**_address_fields(), episode_id=None)
    assert natural.episode_id is None
    assert str(natural.run_id) == S.SAMPLE_UUID


def test_1187_o2_run_name_fault_still_tells_a_sidecar_from_a_run():
    from defender.run_repository import run_name_fault

    run_id = S.new_id()
    assert run_name_fault(run_id) is None, "a plain canonical UUID is a run"
    for suffix in S.SIDECAR_SUFFIXES:
        why = run_name_fault(run_id + suffix)
        assert why, f"{run_id + suffix!r} was admitted as a run name"
    staged = run_name_fault(f"{run_id}.run-end.json{H.STAGED_TAIL}")
    assert staged, "a staged sidecar was admitted as a run name"


# O3 / declared change 4: the family gate no longer judges the composed `<episode>-<label>`.

#: A world label that is valid by its own rule (lower-case letters and digits, 200 bytes) but
#: would make `<36-byte uuid>-<label>` 237 bytes: over the 206-byte bound the gate used to apply
#: to the composed name. Far below NAME_MAX, so no filesystem rule is the reason it is refused.
LONG_LABEL = "w" * 200


def _family_doc_for(episode_id: str, *labels: str) -> dict:
    """The committed family document builder, rewritten to this episode id and to a control world `a` plus one world per label."""
    worlds = [T947.base_world()] + [T947.world_doc(label) for label in labels]
    return T947.family_doc(episode_id=episode_id, worlds=worlds)


@pytest.mark.parametrize("label", ["b", LONG_LABEL, "w" * 220, "w" * 1000, "a-b"],
                         ids=["short", "200-bytes", "220-bytes", "1000-bytes", "invalid"])
def test_1187_o3_labels_follow_their_own_rule(label):
    from defender.runtime.branch import _family

    doc = _family_doc_for(S.new_id(), label)
    if label == "a-b":
        err = S.raised(_family.parse_family, doc)
        assert isinstance(err, _family.FamilyError), err
        assert label in S.message(err)
    else:
        family = _family.parse_family(doc)
        _family.check_identities(family)
        assert [w.label for w in family.worlds] == ["a", label]


def _attribute(obj: object, name: str) -> tuple[str, object]:
    """`("absent", None)`, `("raised", the exception)` or `("value", the value)` of `obj.<name>` — a property may be gone, refuse, or answer."""
    try:
        return "value", getattr(obj, name)
    except AttributeError:
        return "absent", None
    except Exception as exc:  # noqa: BLE001 — a property that refuses is an answer here
        return "raised", exc


def test_1187_o1_a_resumed_world_never_composes_its_arm_id(tmp_path):
    from defender.run_repository import RunId
    from defender.runtime.branch import _family

    episode_id = S.new_id()
    family = _family.parse_family(_family_doc_for(episode_id, "b"))
    roster = {family.world(label).world_id: RunId.parse(S.new_id()) for label in ("a", "b")}
    faults = []
    for label in ("a", "b"):
        composed = f"{episode_id}-{label}"
        handed = _family.resume_world_from(family, label, tmp_path, arm_ids=roster)
        kind, value = _attribute(handed, "run_id")
        if kind == "value" and str(value) != str(roster[family.world(label).world_id]):
            faults.append(f"{label}: handed the roster, run_id is {value!r}, not "
                          f"{str(roster[family.world(label).world_id])!r}")
        bare = _family.resume_world_from(family, label, tmp_path)
        kind, value = _attribute(bare, "run_id")
        if kind == "value" and str(value) == composed:
            faults.append(f"{label}: run_id still composes {composed!r}")
    assert faults == [], "ResumeWorld.run_id reads meaning into the episode id:\n  " + (
        "\n  ".join(faults))


def test_1187_o1_the_episode_layout_spells_no_sibling_run_dir():
    from defender.episodes import _episode_paths

    for owner in (_episode_paths.EpisodeLayout, _episode_paths.LAYOUT):
        assert not hasattr(owner, "sibling_run_dir"), (
            f"{owner!r} still spells the composed sibling run dir")
# #1279 O5: no run id on the command line; the minted id is announced first on stdout.

def _run_py(tenant, alert: Path, run_id: str):
    """Drive run.main with `--run-id <id>` while recording the spend seams."""
    rec = P.SiblingRecorder()
    argv = [str(alert), "--tenant", tenant.id, "--run-id", run_id, "--no-learn"]
    status, refusal, stderr = P.drive_run_py(argv, rec)
    return status, refusal, stderr, rec


@pytest.mark.parametrize("text", [pytest.param(S.SAMPLE_UUID, id="canonical-uuid")] + [
    pytest.param(t, id=repr(t)) for t in S.NON_CANONICAL_IDS if t.strip() == t and t])
def test_1279_o5_run_py_rejects_run_id_on_the_command_line(text, tmp_path, data_root):
    """O5: `--run-id` is no longer an argument, whatever it carries; the run stops before setup."""
    t = S.tenant(data_root)
    alert = H.alert_file(tmp_path / "in")

    status, refusal, stderr, rec = _run_py(t, alert, text)

    assert refusal is not None, f"--run-id was accepted: status {status}, order {rec.order}"
    assert "--run-id" in f"{P.refusal_text(refusal)}\n{stderr}", (P.refusal_text(refusal), stderr)
    assert rec.order == [], f"the run went on past a refused argument: {rec.order}"
    runs = Path(location_path(t.runs))
    assert not (runs / text).exists()
    assert not runs.exists() or sorted(runs.iterdir()) == [], sorted(runs.iterdir())


def test_1279_o5_run_py_rejects_the_equals_form_of_run_id(tmp_path, data_root):
    """O5: `--run-id=<uuid>` is refused as the spaced form is."""
    t = S.tenant(data_root)
    rec = P.SiblingRecorder()

    status, refusal, stderr = P.drive_run_py(
        [str(H.alert_file(tmp_path / "in")), "--tenant", t.id, f"--run-id={S.new_id()}",
         "--no-learn"], rec)

    assert refusal is not None, f"status {status}, order {rec.order}"
    assert "--run-id" in f"{P.refusal_text(refusal)}\n{stderr}"
    assert rec.order == []


@pytest.mark.parametrize("update_ticket", [False, True], ids=["plain", "with-ticket"])
def test_1279_o5_the_minted_id_is_the_first_stdout_line_before_the_ticket_and_box(
        tmp_path, data_root, update_ticket):
    """O5: `run_id=<uuid>` is stdout's first line, after setup and before ticket and lifecycle."""
    t = S.tenant(data_root)
    alert = H.alert_file(tmp_path / "in")
    rec = P.SiblingRecorder()
    argv = [str(alert), "--tenant", t.id, "--no-learn"] + (["--update-ticket"] if update_ticket else [])

    ran = P.drive_run_py_stdout(argv, rec)

    assert ran.refusal is None, (P.refusal_text(ran.refusal), ran.err)
    assert ran.rc == 0, (ran.rc, ran.err)
    run_dir = Path(rec.run_dir)
    line = f"run_id={run_dir.name}\n"
    assert S.is_canonical_uuid(run_dir.name), run_dir.name
    assert run_dir.parent == Path(location_path(t.runs))
    assert ran.out.splitlines(keepends=True)[:1] == [line], ran.out
    assert ran.seen["preflight"] == "", f"stdout before setup: {ran.seen['preflight']!r}"
    assert ran.seen["lifecycle"] == line, f"stdout when the box was reached: {ran.seen['lifecycle']!r}"
    if update_ticket:
        assert ran.seen["ticket"] == line, f"stdout when the ticket opened: {ran.seen['ticket']!r}"


def test_1279_o5_the_announce_is_flushed_not_left_in_stdouts_block_buffer(tmp_path, data_root):
    """O5/A6: a launcher reads the child's stdout through a pipe, where stdout is block-buffered.
    With `sys.stdout` a block-buffered text wrapper over a pipe, `run_id=<uuid>` is already in the
    pipe when the box is reached, so run.py flushed it (an unflushed print would sit in the wrapper
    until exit, and the launcher would see no id while the run is alive)."""
    import io
    import os
    import select
    from contextlib import redirect_stdout

    t = S.tenant(data_root)
    alert = H.alert_file(tmp_path / "in")
    rec = P.SiblingRecorder()
    read_end, write_end = os.pipe()
    sink = io.TextIOWrapper(io.BufferedWriter(io.FileIO(write_end, "w", closefd=False)),
                            encoding="utf-8", write_through=False)
    in_pipe: dict[str, bytes] = {}

    def lifecycle_after_reading_the_pipe(**kwargs):
        ready, _, _ = select.select([read_end], [], [], 2)
        in_pipe["at_lifecycle"] = os.read(read_end, 4096) if ready else b""
        return rec.lifecycle(**kwargs)

    try:
        with redirect_stdout(sink):
            rc, refusal, err = P.drive_run_py([str(alert), "--tenant", t.id, "--no-learn"], rec,
                                              lifecycle=lifecycle_after_reading_the_pipe)
        sink.flush()
    finally:
        os.close(write_end)
        os.close(read_end)

    assert refusal is None, (P.refusal_text(refusal), err)
    assert rc == 0, err
    expected = f"run_id={Path(rec.run_dir).name}\n".encode()
    assert in_pipe["at_lifecycle"] == expected, (
        f"the announce was not in the pipe when the box was reached: {in_pipe['at_lifecycle']!r}")


def test_1279_o8_natural_setup_proceeds_beside_other_ids_sidecars(tmp_path, data_root):
    """O8: setup refuses sidecars at ITS id only; other ids' sidecars (every suffix) in the runs
    base neither refuse it nor are cleared."""
    t = S.tenant(data_root)
    alert = H.alert_file(tmp_path / "in")
    runs = Path(location_path(t.runs))
    runs.mkdir(parents=True, exist_ok=True)
    neighbours = [runs / f"{S.new_id()}{suffix}" for suffix in S.SIDECAR_SUFFIXES for _ in range(2)]
    for sidecar in neighbours:
        sidecar.write_text("{}\n", encoding="utf-8")

    from defender import run_common

    run = run_common.materialize_run(alert, tenant=t)

    assert run.run_dir.parent == runs
    assert run.run_dir.is_dir()
    assert all(sidecar.read_text(encoding="utf-8") == "{}\n" for sidecar in neighbours), (
        "setup cleared or rewrote another id's sidecar")


def test_1279_o5_two_runs_announce_two_minted_ids(tmp_path, data_root):
    """O5: each run's setup mints its own id; the announced id names the run folder it made."""
    t = S.tenant(data_root)
    alert = H.alert_file(tmp_path / "in")
    announced = []
    for _ in range(2):
        rec = P.SiblingRecorder()
        ran = P.drive_run_py_stdout([str(alert), "--tenant", t.id, "--no-learn"], rec)
        assert ran.rc == 0, ran.err
        announced.append(("".join(ran.out.splitlines()[:1]), Path(rec.run_dir).name))

    assert announced[0][0] != announced[1][0]
    for line, folder in announced:
        assert line == f"run_id={folder}"
    assert sorted(p.name for p in Path(location_path(t.runs)).iterdir()) == sorted(
        folder for _line, folder in announced)


@pytest.mark.parametrize("var", ["DEFENDER_RUN_ID", "RUN_ID", "DEFENDER_RUNID", "DEFENDER_PINNED_RUN_ID",
                                 "DEFENDER_RUN_UUID"])
def test_1279_o5_no_environment_variable_chooses_the_run_id(tmp_path, data_root, monkeypatch, var):
    """P-B/O5: with a fresh uuid4 in the environment, run.py still announces a minted, different id."""
    t = S.tenant(data_root)
    alert = H.alert_file(tmp_path / "in")
    runs = Path(location_path(t.runs))
    chosen = S.new_id()
    control = P.drive_run_py_stdout([str(alert), "--tenant", t.id, "--no-learn"], P.SiblingRecorder())
    assert control.rc == 0, (control.rc, control.out, control.err)
    assert control.out.startswith("run_id="), (control.rc, control.out, control.err)
    monkeypatch.setenv(var, chosen)
    rec = P.SiblingRecorder()

    ran = P.drive_run_py_stdout([str(alert), "--tenant", t.id, "--no-learn"], rec)

    assert ran.rc == 0, (ran.rc, ran.err, P.refusal_text(ran.refusal))
    announced = ran.out.splitlines()[0].removeprefix("run_id=")
    assert S.is_canonical_uuid(announced), ran.out
    assert announced != chosen, f"{var} chose the run's id"
    assert Path(rec.run_dir) == runs / announced
    assert not os.path.lexists(runs / chosen), f"{var} named a run folder"


def test_1279_o5_a_run_refused_before_setup_announces_nothing(tmp_path, data_root):
    """O5: nothing is on stdout before the announcement, and a refused start has none."""
    S.tenant(data_root)
    rec = P.SiblingRecorder()

    ran = P.drive_run_py_stdout(
        [str(H.alert_file(tmp_path / "in")), "--tenant", S.new_id()[:8], "--no-learn"], rec)

    assert ran.refusal is not None, f"an unknown tenant ran: {ran.rc}"
    assert ran.out == "", f"stdout before setup: {ran.out!r}"
    assert rec.order == []


def test_1279_a3_setup_and_create_take_no_run_id(tmp_path, data_root):
    """A3: no id parameter on `materialize_run`, `run.py`'s seam or `create()`; `create()` mints."""
    import inspect

    from defender import run as run_py
    from defender import run_common
    from defender.run_repository import EpisodeRuns, RunsRepository

    seam = inspect.signature(run_py.main).parameters["materialize"].default
    for func in (run_common.materialize_run, run_py._materialize_run, RunsRepository.create, seam):
        said = set(inspect.signature(func).parameters) & {"run_id", "pinned", "id"}
        assert said == set(), f"{func.__qualname__} still takes {sorted(said)}"
        open_ended = [p.name for p in inspect.signature(func).parameters.values()
                      if p.kind in (p.VAR_POSITIONAL, p.VAR_KEYWORD)]
        assert open_ended == [], f"{func.__qualname__} takes *args/**kwargs {open_ended}: an id could ride them"
    K = inspect.Parameter
    for func, positional in ((run_common.materialize_run, ["alert"]), (run_py._materialize_run, ["alert"]),
                             (RunsRepository.create, ["self"])):
        params = list(inspect.signature(func).parameters.values())
        got = [p.name for p in params if p.kind is K.POSITIONAL_OR_KEYWORD]
        assert got == positional, f"{func.__qualname__} takes positional {got}, not {positional}"
        for p in params:
            if p.name in positional:
                continue
            assert p.kind is K.KEYWORD_ONLY, f"{func.__qualname__}: {p.name!r} is not keyword-only"
            assert p.default is not p.empty or p.name in ("tenant", "model"), (
                f"{func.__qualname__}: {p.name!r} is required")
            assert "id" not in p.name.casefold().replace("valid", ""), (
                f"{func.__qualname__} takes an id-like parameter {p.name!r}")
    assert seam is run_py._materialize_run, "run.main's materialize seam defaults to run setup's helper"
    params = list(inspect.signature(RunsRepository.create).parameters.values())
    assert params[0].name == "self", params
    for param in params[1:]:
        assert param.default is not param.empty, f"create() requires {param.name!r}: it takes no caller input"
        assert "id" not in param.name.casefold().replace("valid", ""), (
            f"create() takes an id-like parameter {param.name!r}")
    assert len(inspect.signature(EpisodeRuns.create).parameters) == 2, (
        "EpisodeRuns.create keeps its arm id: the roster check needs it")

    t = S.tenant(data_root)
    runs = t.runs_repository()
    assert isinstance(S.raised(runs.create, S.new_id()), TypeError), "create took an id"
    made = [runs.create() for _ in range(3)]
    names = [Path(r.run_dir).name for r in made]
    assert len(set(names)) == 3, names
    assert all(S.is_canonical_uuid(n) for n in names), names
    alert = H.alert_file(tmp_path / "in")
    assert isinstance(S.raised(run_common.materialize_run, alert, S.new_id(), tenant=t),
                      TypeError), "materialize_run took an id"


# O1: the census. No production source composes, derives or bounds an id by meaning.

#: Functions production must neither call nor pass around (C1 of the design): the stamp-label
#: minter, the `-n<message>` episode-id deriver, the held-out folder-name matcher, and #1257's
#: composer of an arm id. A *definition* alone is not flagged: the contract is "nothing calls".
BANNED_FUNCTIONS = frozenset({"mint_run_id", "episode_id_for", "_claimed_slug", "arm_run_id_for",
                              "world_token_for", "episode_token_for"})
#: The 206-byte bound's constant: neither defined nor read.
BANNED_CONSTANT = "RUN_ID_MAX_BYTES"

_astlib = _by_path.import_lint_lib("_astlib")


@dataclass(frozen=True, order=True)
class Hit:
    """One site the census found: where, what shape, and the spelling or origin."""

    rel: str
    line: int
    kind: str
    what: str

    def __str__(self) -> str:
        return f"{self.rel}:{self.line} {self.kind} {self.what}"


def census(root: Path, *, skip_tests: bool = True) -> list[Hit]:
    """Find production sites that derive meaning from run or episode identifiers."""
    root = Path(root)
    excluded = (".venv", "__pycache__", "node_modules") + (("tests",) if skip_tests else ())
    hits: list[Hit] = []
    parsed = []
    for rel in _astlib.source_files(root, excluded):
        _text, tree = _astlib.read_and_parse(root / rel, rel)
        module, package = _astlib.module_and_package(rel, root="defender")
        parsed.append((rel, tree, _astlib.module_env(tree, module, package)))
    composers = _composers([tree for _rel, tree, _env in parsed])
    for rel, tree, env in parsed:
        with _astlib.scan_guard(rel):
            for node, values in S.scoped_nodes(tree):
                hits.extend(_hits_at(node, env, rel, values))
                hits.extend(_composer_calls(node, rel, values, composers))
    return sorted(set(hits))


def _joined_params(func: ast.FunctionDef | ast.AsyncFunctionDef) -> dict[int, str]:
    """Find function parameters joined to separators in identifier compositions."""
    args = [a.arg for a in (*func.args.posonlyargs, *func.args.args)]
    values = S.bound_values(func)

    def reaches(node: ast.AST, name: str, seen: frozenset[str] = frozenset()) -> bool:
        for n in (x for x in ast.walk(node) if isinstance(x, ast.Name)):
            if n.id == name or (n.id not in seen and any(
                    reaches(v, name, seen | {n.id}) for v in values.get(n.id, ()))):
                return True
        return False

    out: dict[int, str] = {}
    for node in ast.walk(func):
        fields: list[ast.AST] = []
        if isinstance(node, ast.JoinedStr):
            fields = [f.value for f, after in zip(node.values, node.values[1:], strict=False)
                      if isinstance(f, ast.FormattedValue) and isinstance(after, ast.Constant)
                      and isinstance(after.value, str) and after.value.startswith("-")]
        elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add) and isinstance(
                node.right, ast.Constant) and isinstance(node.right.value, str) and (
                node.right.value.startswith("-")):
            fields = [_rightmost(node.left)]
        offset = 1 if args[:1] in (["self"], ["cls"]) else 0
        out.update({index - offset: name for index, name in enumerate(args)
                    if index >= offset and any(reaches(f, name) for f in fields)})
    return out


def _composers(trees: list[ast.Module]) -> dict[str, dict[int, str]]:
    """`{function or method name: {call position: parameter}}` over every file: the functions `_joined_params` finds."""
    out: dict[str, dict[int, str]] = {}
    for tree in trees:
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and (
                    joined := _joined_params(node)):
                out.setdefault(node.name, {}).update(joined)
    return out


def _composer_calls(node: ast.AST, rel: str, values: dict,
                    composers: dict[str, dict[int, str]]) -> list[Hit]:
    """Find composing calls whose joined parameter receives an episode identifier."""
    if not isinstance(node, ast.Call):
        return []
    func = node.func
    name = func.id if isinstance(func, ast.Name) else func.attr if isinstance(
        func, ast.Attribute) else None
    joined = composers.get(name or "")
    if not joined:
        return []
    handed = [(i, a) for i, a in enumerate(node.args)] + [
        (next((i for i, p in joined.items() if p == k.arg), -1), k.value)
        for k in node.keywords]
    if any(i in joined and _names_episode_id(a, values) for i, a in handed):
        return [Hit(rel, node.lineno, "composer", ast.unparse(node))]
    return []


def _banned_origin(origin: str | None) -> str | None:
    """The banned name an import-resolved origin ends in, if any."""
    last = origin.rsplit(".", 1)[-1] if origin else None
    return last if last in BANNED_FUNCTIONS or last == BANNED_CONSTANT else None


def _hits_at(node: ast.AST, env, rel: str, values: dict) -> list[Hit]:
    return [*_composed(node, rel, values), *_concatenated(node, rel, values),
            *_banned_use(node, env, rel), *_banned_text(node, rel),
            *_labelled_mint(node, env, rel)]


def _names_episode_id(node: ast.AST, values: dict) -> bool:
    """Recognize episode_id directly or through a locally bound alias."""
    return S.spells(node, "episode_id", values)


def _rightmost(node: ast.expr) -> ast.expr:
    """The last operand of a `+` chain (`a + b + c` is `(a + b) + c`)."""
    while isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        node = node.right
    return node


def _concatenated(node: ast.AST, rel: str, values: dict) -> list[Hit]:
    """`concat` hits: an `episode_id` joined to a `-` by `+`, `str.join`, `str.format` or `%`."""
    def text(n: ast.AST) -> str | None:
        return n.value if isinstance(n, ast.Constant) and isinstance(n.value, str) else None

    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        right = text(node.right)
        if right is not None and right.startswith("-") and _names_episode_id(
                _rightmost(node.left), values):
            return [Hit(rel, node.lineno, "concat", ast.unparse(node))]
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
        fmt = text(node.left)
        if fmt is not None and "-%" in fmt and _names_episode_id(node.right, values):
            return [Hit(rel, node.lineno, "concat", ast.unparse(node))]
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        fmt = text(node.func.value)
        named = any(_names_episode_id(a, values) for a in (*node.args, *node.keywords))
        if fmt == "-" and node.func.attr == "join" and named:
            return [Hit(rel, node.lineno, "concat", ast.unparse(node))]
        if fmt is not None and "}-" in fmt and node.func.attr == "format" and named:
            return [Hit(rel, node.lineno, "concat", ast.unparse(node))]
    return []


def _composed(node: ast.AST, rel: str, values: dict) -> list[Hit]:
    """`fstring` hits: a replacement field naming `episode_id` (directly or through a local alias) followed at once by a `-`."""
    out: list[Hit] = []
    if isinstance(node, ast.JoinedStr):
        for field, after in zip(node.values, node.values[1:], strict=False):
            if (isinstance(field, ast.FormattedValue)
                    and isinstance(after, ast.Constant) and isinstance(after.value, str)
                    and after.value.startswith("-")
                    and _names_episode_id(field.value, values)):
                out.append(Hit(rel, node.lineno, "fstring", "{" + ast.unparse(field.value) + "}-"))
    return out


def _banned_use(node: ast.AST, env, rel: str) -> list[Hit]:
    """`ref` hits (a banned function or the constant used, however it is reached) and the constant's `def`."""
    out: list[Hit] = []
    if isinstance(node, (ast.Name, ast.Attribute)) and isinstance(node.ctx, ast.Load):
        scope = env.scope_of.get(node, env)
        banned = _banned_origin(_astlib.origin(node, env))
        if banned is None and isinstance(node, ast.Name) and node.id in scope.own_defs and (
                node.id in BANNED_FUNCTIONS):
            banned = node.id
        if banned is not None:
            out.append(Hit(rel, node.lineno, "ref", banned))
    if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store) and (
            node.id == BANNED_CONSTANT):
        out.append(Hit(rel, node.lineno, "def", node.id))
    return out


def _banned_text(node: ast.AST, rel: str) -> list[Hit]:
    """`str` hits: a banned name as a string constant (an `__all__` re-export)."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str) and (
            node.value in BANNED_FUNCTIONS or node.value == BANNED_CONSTANT):
        return [Hit(rel, node.lineno, "str", node.value)]
    return []


def _labelled_mint(node: ast.AST, env, rel: str) -> list[Hit]:
    """Find RunId.mint calls that pass a label or clock, including import aliases."""
    if isinstance(node, ast.Call) and (node.args or node.keywords):
        called = _astlib.callee(node, env)
        func = node.func
        if (called is None and isinstance(func, ast.Call) and _astlib.callee(func, env) == (
                "builtins.getattr") and len(func.args) == 2
                and isinstance(func.args[1], ast.Constant) and func.args[1].value == "mint"):
            owner = _astlib.origin(func.args[0], env)
            called = f"{owner}.mint" if owner is not None else None
        if called is not None and called.endswith("RunId.mint"):
            return [Hit(rel, node.lineno, "mint-args", called)]
    return []


def test_1187_o1_no_production_source_composes_derives_or_bounds_an_id_by_meaning():
    hits = census(DEFENDER)
    listing = "\n  ".join(str(h) for h in hits)
    assert hits == [], f"{len(hits)} production sites still read or build id meaning:\n  {listing}"


# #1279 A3 census: no production call hands a run id to run setup or `RunsRepository.create`;
# only run setup makes an arm, from the roster's id.

def run_id_handouts(root: Path, *, skip_tests: bool = True) -> list[Hit]:
    """Production calls that pass an id to setup or `create`, and every arm `create`."""
    root = Path(root)
    excluded = (".venv", "__pycache__", "node_modules") + (("tests",) if skip_tests else ())
    hits: list[Hit] = []
    for rel in _astlib.source_files(root, excluded):
        _text, tree = _astlib.read_and_parse(root / rel, rel)
        module, package = _astlib.module_and_package(rel, root="defender")
        env = _astlib.module_env(tree, module, package)
        with _astlib.scan_guard(rel):
            for node, values in S.scoped_nodes(tree):
                hits.extend(_handouts_at(node, env, rel, values))
    return sorted(set(hits))


def _splats(node: ast.Call) -> bool:
    """Does the call spread a mapping or sequence (`**m`, `*a`) that could carry an id?"""
    return any(k.arg is None for k in node.keywords) or any(
        isinstance(a, ast.Starred) for a in node.args)


def _handouts_at(node: ast.AST, env, rel: str, values: dict) -> list[Hit]:
    if not isinstance(node, ast.Call):
        return []
    func = node.func
    called = _astlib.callee(node, env) or ""
    named = {k.arg for k in node.keywords}
    handed = len(node.args) > 1 or bool(named & {"run_id", "pinned"}) or _splats(node)
    seam = isinstance(func, ast.Name) and func.id in ("materialize", "_materialize_run")
    if called.rsplit(".", 1)[-1] in ("materialize_run", "_materialize_run") or seam:
        return [Hit(rel, node.lineno, "setup-id", ast.unparse(node))] if handed else []
    if not (isinstance(func, ast.Attribute) and func.attr == "create"):
        return []
    receiver = func.value
    if S.spells(receiver, "runs_repository", values):  # direct, or through any local alias
        return [Hit(rel, node.lineno, "repo-id", ast.unparse(node))] if (
            node.args or node.keywords) else []
    if S.spells(receiver, "episode_runs", values):
        sourced = bool(node.args) and S.spells(node.args[0], "arm_id", values) and not _splats(node)
        return [Hit(rel, node.lineno, "arm-create" if sourced else "arm-create-foreign",
                    ast.unparse(node))]
    if _splats(node) or named & {"run_id", "pinned"}:  # a receiver that may be the repo
        return [Hit(rel, node.lineno, "create-spread", ast.unparse(node))]
    return []


def test_1279_a3_census_no_production_call_hands_a_run_id_to_setup_or_create():
    hits = run_id_handouts(DEFENDER)
    listing = "\n  ".join(str(h) for h in hits)

    handed = [h for h in hits if h.kind != "arm-create"]
    assert handed == [], f"production hands an id around:\n  {listing}"
    assert [(h.rel, h.kind) for h in hits] == [("run_common.py", "arm-create")], (
        f"only run setup makes an arm, from the roster's arm id:\n  {listing}")


RUN_ID_HANDOUTS = [
    ("setup-positional", "run_common.materialize_run(alert, rid, tenant=t)", [("setup-id",)]),
    ("setup-keyword", "run_common.materialize_run(alert, tenant=t, run_id=rid)", [("setup-id",)]),
    ("setup-pinned", "run_common.materialize_run(alert, tenant=t, pinned=True)", [("setup-id",)]),
    ("setup-alias", "mat(alert, rid, tenant=t)", [("setup-id",)]),
    ("run-py-helper", "_materialize_run(alert, rid, tenant=t, model=m)", [("setup-id",)]),
    ("seam", "materialize(alert, rid, tenant=t)", [("setup-id",)]),
    ("repo-positional", "t.runs_repository().create(rid)", [("repo-id",)]),
    ("repo-pinned", "t.runs_repository().create(pinned=True)", [("repo-id",)]),
    ("arm-from-roster", "episode_runs.create(episode_runs.arm_id(world.world_id))",
     [("arm-create",)]),
    ("arm-from-local", "arm = episode_runs.arm_id(world.world_id)\nepisode_runs.create(arm)",
     [("arm-create",)]),
    ("arm-from-elsewhere", "episode_runs.create(rid)", [("arm-create-foreign",)]),
    ("arm-through-alias", "view = episode_runs\nview.create(rid)", [("arm-create-foreign",)]),
    ("setup-splat", "ctx = {'run_id': rid}\nrun_common.materialize_run(alert, tenant=t, **ctx)",
     [("setup-id",)]),
    ("seam-splat", "pin = {'run_id': rid}\nmaterialize(alert, tenant=t, model=m, **pin)",
     [("setup-id",)]),
    ("run-py-helper-splat", "_materialize_run(alert, tenant=t, model=m, **ctx)", [("setup-id",)]),
    ("repo-through-variable", "repo = t.runs_repository()\nrepo.create(rid)", [("repo-id",)]),
    ("repo-splat-through-variable", "repo = t.runs_repository()\nrepo.create(**ctx)",
     [("repo-id",)]),
    ("repo-through-two-names", "a = t.runs_repository()\nb = a\nb.create(run_id=rid)",
     [("repo-id",)]),
    ("repo-from-parameter-splat", "other.create(**ctx)", [("create-spread",)]),
    ("arm-splat", "episode_runs.create(*[episode_runs.arm_id(world.world_id)])",
     [("arm-create-foreign",)]),
    ("clean-setup", "run_common.materialize_run(alert, tenant=t, model=m, world=w)", []),
    ("clean-repo-variable", "repo = t.runs_repository()\nrepo.create()", []),
    ("clean-seam", "materialize(alert, tenant=t, model=m)", []),
    ("clean-repo", "t.runs_repository().create()", []),
    ("unrelated-create", "episode.source_alert.create(raw)\nother.create(rid)", []),
]


@pytest.mark.parametrize(("name", "body", "expected"), RUN_ID_HANDOUTS,
                         ids=[c[0] for c in RUN_ID_HANDOUTS])
def test_1279_a3_census_partitions(tmp_path, name, body, expected):
    import textwrap

    source = ("from defender import run_common\n"
              "from defender.run_common import materialize_run as mat\n"
              "def _materialize_run(*a, **k):\n    pass\n"
              "def check(t, alert, rid, m, w, materialize, episode_runs, world, episode, other, raw):\n"
              + textwrap.indent(body, "    ") + "\n")
    (tmp_path / "probe.py").write_text(source, encoding="utf-8")

    assert [(h.kind,) for h in run_id_handouts(tmp_path)] == expected, (name, source)


# Each syntax partition has an exact oracle, including import aliases and negative controls.
IDENTITY_SYNTAX = [
    ("bare-fstring", "return f'{episode_id}-{label}'", [("fstring", "{episode_id}-")]),
    ("attribute-fstring", "return f'{family.episode_id}-r2'", [("fstring", "{family.episode_id}-")]),
    ("import-alias", "return m('x')", [("ref", "mint_run_id")]),
    ("module-attribute", "return _run_id.mint_run_id('y')", [("ref", "mint_run_id")]),
    ("local-deriver", "return episode_id_for(label)", [("ref", "episode_id_for")]),
    ("world-deriver", "return family_model.world_token_for(episode_id, label)",
     [("ref", "world_token_for")]),
    ("episode-deriver", "return family_model.episode_token_for(episode_id)",
     [("ref", "episode_token_for")]),
    ("labelled-mint", "return RunId.mint(label)", [("mint-args", "defender.run_repository.RunId.mint")]),
    ("add", "return family.episode_id + '-' + label", [("concat", "family.episode_id + '-'")]),
    ("join", "return '-'.join([episode_id, label])", [("concat", "'-'.join([episode_id, label])")]),
    ("format", "return '{}-{}'.format(episode_id, label)",
     [("concat", "'{}-{}'.format(episode_id, label)")]),
    ("percent", "return '%s-%s' % (episode_id, label)", [("concat", "'%s-%s' % (episode_id, label)")]),
    ("aliases", """    ep = episode_id
    eid: str = family.episode_id
    first = ep
    second = first
    a = f'{ep}-{label}'
    b = f'{eid}-r{n}'
    c = f'{second}-{label}'
    d = ep + '-' + label
    e = getattr(RunId, 'mint')(label)
    if (w := family.episode_id):
        return f'{w}-x'
    return a, b, c, d, e""", [
        ("fstring", "{ep}-"), ("fstring", "{eid}-"), ("fstring", "{second}-"),
        ("concat", "ep + '-'"), ("mint-args", "defender.run_repository.RunId.mint"), ("fstring", "{w}-")]),
    ("composer", "return compose(family.episode_id, label)",
     [("composer", "compose(family.episode_id, label)")]),
    ("class-attribute", """class Holder:
    def __init__(self, family):
        self._eid = family.episode_id
    def arm(self, label):
        return f'{self._eid}-{label}'""", [("fstring", "{self._eid}-")]),
    ("constant", "RUN_ID_MAX_BYTES = 206", [("def", BANNED_CONSTANT)]),
    ("re-export", "__all__ = ['episode_id_for']", [("str", "episode_id_for")]),
    ("ordinary-text", """    note = f'{label}-{n} for {episode_id} - done'
    joined = '-'.join([label, str(n)]) + label + '-x' + episode_id
    said = 'episode %s - %s' % (episode_id, n)
    return note, f'{episode_id}', RunId.mint(), joined, said""", []),
    ("separate-scopes", """def binds(episode_id):
    ep = episode_id
    return ep
def other_scope(label, n):
    ep = label
    return f'{ep}-{n}', getattr(RunId, 'mint')()""", []),
    ("ordinary-composer", """def stamp(prefix, n):
    return f'{prefix}-{n}'
def uses_stamp(label, n):
    return stamp(label, n)""", []),
    ("ordinary-attribute", """class Plain:
    def __init__(self, label):
        self._label = label
    def name(self, n):
        return f'{self._label}-{n}'""", []),
    ("unused-definition", "def mint_run_id():\n    return RunId.mint()", []),
]


@pytest.mark.parametrize(("name", "source", "expected"), IDENTITY_SYNTAX, ids=[c[0] for c in IDENTITY_SYNTAX])
def test_1187_o1_census_syntax_partitions(tmp_path, name, source, expected):
    import textwrap

    prefix = ("from defender._run_id import mint_run_id as m\n"
              "from defender.runtime.branch import _family as family_model\n"
              "from defender import _run_id\nfrom defender.run_repository import RunId\n"
              "def episode_id_for(src):\n    return src\n"
              "def compose(eid, label):\n    joined = eid\n    return f'{joined}-{label}'\n")
    if source.startswith(("class ", "def ", "RUN_", "__all__")):
        module = source
    else:
        body = textwrap.indent(textwrap.dedent(source), "    ")
        module = "def check(family, episode_id, label, n):\n" + body
    path = tmp_path / "probe.py"
    path.write_text(prefix + module + "\n", encoding="utf-8")
    found = [(hit.kind, hit.what) for hit in census(tmp_path)]
    assert sorted(found) == sorted(expected), (name, found)


def test_1187_o1_the_census_leaves_tests_out(tmp_path):
    root = tmp_path / "planted"
    (root / "tests").mkdir(parents=True)
    (root / "tests" / "old.py").write_text(
        "def f(episode_id, label):\n    return f'{episode_id}-{label}'\n", encoding="utf-8")

    assert census(root) == []
    assert [h.kind for h in census(root, skip_tests=False)] == ["fstring"]
