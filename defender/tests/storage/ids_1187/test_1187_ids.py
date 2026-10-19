"""Run and episode identities are canonical UUIDs with no labels or composed meaning."""
from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path

import pytest

from defender.tests.support.shared.contracts import _by_path
from defender.tests.support.learning.branch import _triplet_947 as T947
from defender.tests.storage.ids_1187 import _spec1187 as S
from defender.tests.storage.tenant_1105_run_repository import _spec1105 as H
from defender.tests.storage.tenant_1105_run_repository import _spec1105_pr2 as P

DEFENDER = Path(__file__).resolve().parents[3]


def _param(text: str) -> pytest.param:
    """One non-canonical id as a test case, readable in the test id (`''`, `'..'`, ...)."""
    return pytest.param(text, id=repr(text))


NON_CANONICAL = [_param(text) for text in S.NON_CANONICAL_IDS]
# O1 / declared change 2: a minted id is a bare random UUID.

def test_1187_o1_mint_returns_canonical_lowercase_uuid4_text():
    import uuid

    from defender.run_repository import RunId

    minted = RunId.mint()
    text = str(minted)
    assert type(minted) is RunId, f"mint() gave {minted!r}"
    assert S.is_canonical_uuid(text), f"a minted id is not canonical lowercase UUID text: {text!r}"
    assert uuid.UUID(text).version == 4, f"a minted id is not a uuid4: {text!r}"
    assert RunId.parse(text) == minted


def test_1187_o1_a_thousand_mints_are_distinct():
    from defender.run_repository import RunId

    texts = {str(RunId.mint()) for _ in range(1000)}
    assert len(texts) == 1000, f"{1000 - len(texts)} of 1000 minted ids repeated an earlier one"


def test_1187_o1_mint_takes_no_alert_label():
    from defender.run_repository import RunId

    labelled = S.raised(RunId.mint, "login-brute")
    assert labelled is not None, "mint accepted an alert label"
    assert S.is_canonical_uuid(str(RunId.mint()))


def test_1187_o1_run_setup_names_an_unpinned_run_folder_by_a_bare_uuid(tmp_path, data_root):
    from defender import run_common

    t = S.tenant(data_root)
    alert = H.alert_file(tmp_path / "in", "ssh-brute-force.json")

    first = run_common.materialize_run(alert, None, tenant=t)
    second = run_common.materialize_run(alert, None, tenant=t)

    runs = Path(t.runs)
    assert Path(first.run_dir).parent == runs
    assert Path(second.run_dir).parent == runs
    for run in (first, second):
        name = Path(run.run_dir).name
        assert S.is_canonical_uuid(name), f"the minted run folder is named {name!r}"
        assert Path(run.run_dir).is_dir()
    assert Path(first.run_dir).name != Path(second.run_dir).name
# O2 / declared change 1: only canonical lowercase UUID text is an id.

def test_1187_o2_run_id_parse_admits_a_canonical_uuid():
    from defender.run_repository import RunId

    for text in (S.SAMPLE_UUID, S.new_id()):
        assert str(RunId.parse(text)) == text


@pytest.mark.parametrize("text", NON_CANONICAL)
def test_1187_o2_run_id_parse_refuses_a_non_canonical_id(text):
    from defender.run_repository import RunId, RunRefused

    err = S.raised(RunId.parse, text)
    assert S.is_a(err, RunRefused), f"RunId.parse({text!r}) gave {err!r}"


@pytest.mark.parametrize("text", NON_CANONICAL)
def test_1187_o2_run_id_fault_and_episode_id_fault_refuse_a_non_canonical_id(text):
    from defender.records._run_id import episode_id_fault, run_id_fault

    for rule in (run_id_fault, episode_id_fault):
        why = rule(text)
        assert isinstance(why, str), f"{rule.__name__}({text!r}) answered {why!r}"
        assert why, f"{rule.__name__}({text!r}) answered an empty sentence"
    for rule in (run_id_fault, episode_id_fault):
        assert rule(S.SAMPLE_UUID) is None, f"{rule.__name__} refused a canonical UUID"
        assert rule(S.new_id()) is None


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


@pytest.mark.parametrize("text", NON_CANONICAL)
def test_1187_o2_run_address_refuses_a_non_canonical_run_id(text):
    from defender.run_repository import RunAddress

    err = S.raised(RunAddress, tenant_id=_address_fields()["tenant_id"], run_id=text,
                   episode_id=None)
    assert err is not None, f"RunAddress admitted the run id {text!r}"


@pytest.mark.parametrize("text", NON_CANONICAL)
def test_1187_o2_run_address_refuses_a_non_canonical_episode_id(text):
    from defender.run_repository import RunAddress

    err = S.raised(RunAddress, **_address_fields(), episode_id=text)
    assert err is not None, f"RunAddress admitted the episode id {text!r}"


def test_1187_o2_run_name_fault_still_tells_a_sidecar_from_a_run():
    from defender.run_repository import run_name_fault

    run_id = S.new_id()
    assert run_name_fault(run_id) is None, "a plain canonical UUID is a run"
    for suffix in S.SIDECAR_SUFFIXES:
        why = run_name_fault(run_id + suffix)
        assert why, f"{run_id + suffix!r} was admitted as a run name"
    staged = run_name_fault(f"{run_id}.run-end.json{H.STAGED_TAIL}")
    assert staged, "a staged sidecar was admitted as a run name"


def test_1187_o2_the_listing_takes_a_uuid_runs_sidecars_as_sidecars_not_as_runs(data_root):
    t = S.tenant(data_root)
    run_id = S.new_id()
    S.make_run(S.natural_runs(data_root, H.T_ID), run_id, sidecars=True)
    beside = sorted(p.name for p in S.natural_runs(data_root, H.T_ID).iterdir())
    assert beside == sorted([run_id, *(run_id + s for s in S.SIDECAR_SUFFIXES)]), beside

    listed = t.runs_repository().list()

    assert [str(r) for r in listed] == [run_id]
# O3 / declared change 4: the family gate no longer judges the composed `<episode>-<label>`.

#: A world label that is valid by its own rule (lower-case letters and digits, 200 bytes) but
#: would make `<36-byte uuid>-<label>` 237 bytes: over the 206-byte bound the gate used to apply
#: to the composed name. Far below NAME_MAX, so no filesystem rule is the reason it is refused.
LONG_LABEL = "w" * 200


def _family_doc_for(episode_id: str, *labels: str) -> dict:
    """The committed family document builder, rewritten to this episode id and to a control world `a` plus one world per label."""
    worlds = [T947.base_world()] + [T947.world_doc(label) for label in labels]
    return T947.family_doc(episode_id=episode_id, worlds=worlds)


def test_1187_o3_the_family_gate_does_not_refuse_a_label_for_a_long_composed_name():
    from defender.runtime.branch import _family

    episode_id = S.new_id()
    short = _family.parse_family(_family_doc_for(episode_id, "b"))
    _family.check_identities(short)

    long_doc = _family_doc_for(episode_id, LONG_LABEL)
    family = _family.parse_family(long_doc)
    _family.check_identities(family)
    assert [w.world_id for w in family.worlds] == ["a", LONG_LABEL]


def test_1187_o3_a_label_is_still_held_to_its_own_rule():
    from defender.runtime.branch import _family

    episode_id = S.new_id()
    _family.parse_family(_family_doc_for(episode_id, "b"))
    err = S.raised(_family.parse_family, _family_doc_for(episode_id, "a-b"))
    assert S.is_a(err, _family.FamilyError), f"a label 'a-b' gave {err!r}"
    assert "a-b" in S.message(err), S.message(err)


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
    roster = {label: RunId.parse(S.new_id()) for label in ("a", "b")}
    faults = []
    for label in ("a", "b"):
        composed = f"{episode_id}-{label}"
        handed = _family.resume_world_from(family, label, tmp_path, arm_ids=roster)
        kind, value = _attribute(handed, "run_id")
        if kind == "value" and str(value) != str(roster[label]):
            faults.append(f"{label}: handed the roster, run_id is {value!r}, not "
                          f"{str(roster[label])!r}")
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
# O2: `run.py --run-id` refuses an old id and accepts a UUID.

def _run_py(tenant, alert: Path, run_id: str):
    """Drive run.main while recording spending seams without invoking a model or sandbox."""
    rec = P.SiblingRecorder()
    argv = [str(alert), "--tenant", tenant.id, "--run-id", run_id, "--no-learn"]
    status, refusal, stderr = P.drive_run_py(argv, rec)
    return status, refusal, stderr, rec


def test_1187_o2_run_py_runs_a_pinned_uuid(tmp_path, data_root):
    t = S.tenant(data_root)
    alert = H.alert_file(tmp_path / "in")
    run_id = S.new_id()

    status, refusal, stderr, rec = _run_py(t, alert, run_id)

    assert refusal is None, f"--run-id {run_id} was refused: {P.refusal_text(refusal)!r} {stderr!r}"
    assert status == 0, (status, stderr)
    assert rec.order.count("lifecycle") == 1, rec.order
    assert (Path(t.runs) / run_id).is_dir()


@pytest.mark.parametrize("text", [pytest.param(t, id=repr(t)) for t in S.NON_CANONICAL_IDS
                                  if t.strip() == t and t])
def test_1187_o2_run_py_refuses_a_pinned_id_that_is_not_a_canonical_uuid(
        text, tmp_path, data_root):
    t = S.tenant(data_root)
    alert = H.alert_file(tmp_path / "in")

    status, refusal, stderr, rec = _run_py(t, alert, text)

    assert refusal is not None, f"--run-id {text!r} ran: status {status}, order {rec.order}"
    said = P.refusal_text(refusal)
    assert "run id" in said, f"not a run-id refusal: {said!r}"
    # Pre-flight runs before run setup (it spends nothing); the lifecycle, the page and the
    # curation enqueue are what a refused id must never reach.
    assert [step for step in rec.order if step != "preflight"] == [], (
        f"the run went on past a refused id: {rec.order}")
    assert not Path(t.runs).exists() or sorted(Path(t.runs).iterdir()) == [], (
        f"a refused id left something in the runs folder: {sorted(Path(t.runs).iterdir())}")
# O1: the census. No production source composes, derives or bounds an id by meaning.

#: Functions production must neither call nor pass around (C1 of the design): the stamp-label
#: minter, the `-n<message>` episode-id deriver, the held-out folder-name matcher, and #1257's
#: composer of an arm id. A *definition* alone is not flagged: the contract is "nothing calls".
BANNED_FUNCTIONS = frozenset({"mint_run_id", "episode_id_for", "_claimed_slug", "arm_run_id_for"})
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


def test_1187_o1_the_census_finds_what_it_is_meant_to_find(tmp_path):
    root = tmp_path / "planted"
    (root / "pkg").mkdir(parents=True)
    (root / "pkg" / "dirty.py").write_text(
        "from defender._run_id import mint_run_id as m\n"
        "from defender import _run_id\n"
        "from defender.run_repository import RunId\n"
        "\n"
        "RUN_ID_MAX_BYTES = 206\n"
        "__all__ = ['episode_id_for']\n"
        "\n"
        "\n"
        "def episode_id_for(src):\n"
        "    return src\n"
        "\n"
        "\n"
        "def uses(family, episode_id, label, src):\n"
        "    a = f'{episode_id}-{label}'\n"
        "    b = f'{family.episode_id}-r2'\n"
        "    c = m('x')\n"
        "    d = _run_id.mint_run_id('y')\n"
        "    e = episode_id_for(src)\n"
        "    g = RunId.mint('login')\n"
        "    h = family.episode_id + '-' + label\n"
        "    i = '-'.join([episode_id, label])\n"
        "    j = '{}-{}'.format(episode_id, label)\n"
        "    k = '%s-%s' % (episode_id, label)\n"
        "    return a, b, c, d, e, g, h, i, j, k\n"
        "\n"
        "\n"
        "def aliased(family, episode_id, label, n):\n"
        "    ep = episode_id\n"
        "    eid: str = family.episode_id\n"
        "    first = ep\n"
        "    second = first\n"
        "    a = f'{ep}-{label}'\n"
        "    b = f'{eid}-r{n}'\n"
        "    c = f'{second}-{label}'\n"
        "    d = ep + '-' + label\n"
        "    e = getattr(RunId, 'mint')(label)\n"
        "    if (w := family.episode_id):\n"
        "        return f'{w}-x'\n"
        "    return a, b, c, d, e\n"
        "\n"
        "\n"
        "def compose(eid, label):\n"
        "    joined = eid\n"
        "    return f'{joined}-{label}'\n"
        "\n"
        "\n"
        "def passes(family, label):\n"
        "    return compose(family.episode_id, label)\n"
        "\n"
        "\n"
        "class Holder:\n"
        "    def __init__(self, family):\n"
        "        self._eid = family.episode_id\n"
        "\n"
        "    def arm(self, label):\n"
        "        return f'{self._eid}-{label}'\n",
        encoding="utf-8")
    (root / "pkg" / "clean.py").write_text(
        "from defender.run_repository import RunId\n"
        "\n"
        "\n"
        "def mint_run_id():  # a definition alone is not a call\n"
        "    return RunId.mint()\n"
        "\n"
        "\n"
        "def fine(label, n, episode_id):\n"
        "    note = f'{label}-{n} for {episode_id} - done'\n"
        "    joined = '-'.join([label, str(n)]) + label + '-x' + episode_id\n"
        "    said = 'episode %s - %s' % (episode_id, n)\n"
        "    return note, f'{episode_id}', RunId.mint(), joined, said\n"
        "\n"
        "\n"
        "def binds(episode_id):\n"
        "    ep = episode_id\n"
        "    return ep\n"
        "\n"
        "\n"
        "def other_scope(label, n):\n"
        "    ep = label\n"
        "    return f'{ep}-{n}', getattr(RunId, 'mint')()\n"
        "\n"
        "\n"
        "def stamp(prefix, n):\n"
        "    return f'{prefix}-{n}'\n"
        "\n"
        "\n"
        "def uses_stamp(label, n):\n"
        "    return stamp(label, n)\n"
        "\n"
        "\n"
        "class Plain:\n"
        "    def __init__(self, label):\n"
        "        self._label = label\n"
        "\n"
        "    def name(self, n):\n"
        "        return f'{self._label}-{n}'\n",
        encoding="utf-8")

    found = {(h.rel, h.kind, h.what) for h in census(root)}

    dirty = "pkg/dirty.py"
    assert (dirty, "fstring", "{episode_id}-") in found, found
    assert (dirty, "fstring", "{family.episode_id}-") in found, found
    assert (dirty, "ref", "mint_run_id") in found, found      # by alias and by attribute
    assert (dirty, "ref", "episode_id_for") in found, found   # the module's own def, called
    assert (dirty, "def", BANNED_CONSTANT) in found, found
    assert (dirty, "str", "episode_id_for") in found, found
    assert any(h.rel == dirty and h.kind == "mint-args" for h in census(root))
    assert len([h for h in census(root) if h.rel == dirty and h.kind == "concat"]) == 5, (
        [h for h in census(root) if h.kind == "concat"])
    assert [h for h in census(root) if h.rel == "pkg/clean.py"] == []
    assert len([h for h in census(root) if h.kind == "ref" and h.what == "mint_run_id"]) == 2
    # Adversary F1: the same joins through a local alias (`ep = episode_id`, an annotated
    # alias, a chain of two, a walrus) and the mint reached through `getattr`.
    lines = (root / dirty).read_text(encoding="utf-8").splitlines()
    start = lines.index("def aliased(family, episode_id, label, n):") + 1
    aliased = [h for h in census(root) if h.rel == dirty and h.line >= start]
    assert sorted((h.kind, h.what) for h in aliased) == sorted([
        ("fstring", "{ep}-"), ("fstring", "{eid}-"), ("fstring", "{second}-"),
        ("concat", "ep + '-'"), ("mint-args", "defender.run_repository.RunId.mint"),
        ("fstring", "{w}-"),
        # the parameter-passing shape: `compose` spells no episode id (so no fstring hit there), the caller hands one;
        # and the attribute shape: `self._eid` assigned from one, joined in another method.
        ("composer", "compose(family.episode_id, label)"),
        ("fstring", "{self._eid}-")]), aliased


def test_1187_o1_the_census_leaves_tests_out(tmp_path):
    root = tmp_path / "planted"
    (root / "tests").mkdir(parents=True)
    (root / "tests" / "old.py").write_text(
        "def f(episode_id, label):\n    return f'{episode_id}-{label}'\n", encoding="utf-8")

    assert census(root) == []
    assert [h.kind for h in census(root, skip_tests=False)] == ["fstring"]
