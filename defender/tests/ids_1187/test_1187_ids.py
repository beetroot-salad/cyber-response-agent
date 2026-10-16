"""#1187 slice A — ids: every run, arm and episode id is a random canonical UUID (O1, O2, O3).

Design rev 2 (issue comments 6192137519 + 6192137980), declared changes 1, 2 and 4:

* O1 / change 2: `RunId.mint()` takes no argument and returns canonical lowercase uuid4 text; a
  minted id carries no alert label and no time. No production code composes `<episode_id>-...`,
  mints from a label, derives an episode id, matches a fixture from a folder name, or reads the
  206-byte bound (the census, a static scan of production source).
* O2 / change 1: `RunId.parse`, `_run_id.run_id_fault`, `_run_id.episode_id_fault` and
  `RunAddress` (both fields) admit only canonical lowercase UUID text. `run.py --run-id` refuses
  an old id and accepts a UUID. `run_name_fault` still tells a sidecar from a run.
* O3 / change 4: the family gate no longer refuses a world label because `<episode_id>-<label>`
  would be long; the label's own rule still applies.

Every refusal has a positive control through the same channel. Targets are imported inside each
test body, so a missing name fails that test alone. The expected values come from the design's
rule, written in `_spec1187` (`is_canonical_uuid`, `NON_CANONICAL_IDS`), not from production.

Entry surfaces: `RunId.mint` / `RunId.parse`, `run_name_fault`, `RunAddress`, the family model
(`parse_family` + `check_identities`, the gate `_check_labels` sits behind), run setup
(`run_common.materialize_run`), and `run.main` itself with its spend seams.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path

import pytest

from defender.tests import _by_path
from defender.tests import _triplet_947 as T947
from defender.tests.ids_1187 import _spec1187 as S
from defender.tests.tenant_1105_run_repository import _spec1105 as H
from defender.tests.tenant_1105_run_repository import _spec1105_pr2 as P

DEFENDER = Path(__file__).resolve().parents[2]


def _param(text: str) -> pytest.param:
    """One non-canonical id as a test case, readable in the test id (`''`, `'..'`, ...)."""
    return pytest.param(text, id=repr(text))


NON_CANONICAL = [_param(text) for text in S.NON_CANONICAL_IDS]


# ==========================================================================================
# O1 / declared change 2: a minted id is a bare random UUID.
# ==========================================================================================

def test_1187_o1_mint_returns_canonical_lowercase_uuid4_text():
    """#1187 declared change 2. `RunId.mint()` (no argument) returns a `RunId` whose text is
    canonical lowercase UUID text of version 4 — not `<stamp>-<label>` — and parses back to an
    equal `RunId`. RED at base: `mint()` needs its label argument (TypeError)."""
    import uuid

    from defender.run_repository import RunId

    minted = RunId.mint()
    text = str(minted)
    assert type(minted) is RunId, f"mint() gave {minted!r}"
    assert S.is_canonical_uuid(text), f"a minted id is not canonical lowercase UUID text: {text!r}"
    assert uuid.UUID(text).version == 4, f"a minted id is not a uuid4: {text!r}"
    assert RunId.parse(text) == minted


def test_1187_o1_a_thousand_mints_are_distinct():
    """#1187 declared change 2. Ids are random, not derived from a clock tick or a label: a
    thousand mints in one process are a thousand different ids (a stamp-seconds id would repeat
    within a second). RED at base: `mint()` needs its label."""
    from defender.run_repository import RunId

    texts = {str(RunId.mint()) for _ in range(1000)}
    assert len(texts) == 1000, f"{1000 - len(texts)} of 1000 minted ids repeated an earlier one"


def test_1187_o1_mint_takes_no_alert_label():
    """#1187 declared change 2. A label has nowhere to go: `RunId.mint("login-brute")` is refused
    in some way (the spelling of the refusal is the implementer's), where today it mints
    `<stamp>-login-brute`. Positive control: the no-argument form mints. RED at base: the
    labelled call mints, and the control raises."""
    from defender.run_repository import RunId

    labelled = S.raised(RunId.mint, "login-brute")
    assert labelled is not None, "mint accepted an alert label"
    assert S.is_canonical_uuid(str(RunId.mint()))


def test_1187_o1_run_setup_names_an_unpinned_run_folder_by_a_bare_uuid(tmp_path, data_root):
    """#1187 declared change 2, through the real run-setup entry (`run_common.materialize_run`
    with no pinned id) and observed on disk: for an alert file named after its subject, the run
    folder under `<T>/runs` is named by a canonical lowercase UUID alone — no alert label, no
    time — and two setups from the same alert get two different folders. RED at base: the folder
    is `<stamp>-ssh-brute-force`."""
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


# ==========================================================================================
# O2 / declared change 1: only canonical lowercase UUID text is an id.
# ==========================================================================================

def test_1187_o2_run_id_parse_admits_a_canonical_uuid():
    """#1187 declared change 1, positive control for the refusals below: canonical lowercase
    UUID text (the sample, and a fresh one) parses to a `RunId` whose text is the input."""
    from defender.run_repository import RunId

    for text in (S.SAMPLE_UUID, S.new_id()):
        assert str(RunId.parse(text)) == text


@pytest.mark.parametrize("text", NON_CANONICAL)
def test_1187_o2_run_id_parse_refuses_a_non_canonical_id(text):
    """#1187 declared change 1. `RunId.parse` refuses, with `RunRefused`, an old minted id, an
    old pinned slug, an upper-case UUID, braces, a UUID without hyphens, a `urn:uuid:` prefix, a
    UUID with a suffix, surrounding whitespace, `latest`, the empty string and `..`. RED at base
    for the ones today's grammar admits (the old minted and pinned ids, braces-free forms)."""
    from defender.run_repository import RunId, RunRefused

    err = S.raised(RunId.parse, text)
    assert S.is_a(err, RunRefused), f"RunId.parse({text!r}) gave {err!r}"


@pytest.mark.parametrize("text", NON_CANONICAL)
def test_1187_o2_run_id_fault_and_episode_id_fault_refuse_a_non_canonical_id(text):
    """#1187 declared change 1. The two rules in `_run_id` answer with a refusal sentence (a
    non-empty `str`) for each non-canonical id and `None` for a canonical UUID — the episode id
    rule too, which no longer asks for room for `-<label>`."""
    from defender._run_id import episode_id_fault, run_id_fault

    for rule in (run_id_fault, episode_id_fault):
        why = rule(text)
        assert isinstance(why, str), f"{rule.__name__}({text!r}) answered {why!r}"
        assert why, f"{rule.__name__}({text!r}) answered an empty sentence"
    for rule in (run_id_fault, episode_id_fault):
        assert rule(S.SAMPLE_UUID) is None, f"{rule.__name__} refused a canonical UUID"
        assert rule(S.new_id()) is None


def test_1187_o2_episode_id_rule_asks_for_no_room_for_a_label():
    """#1187 declared change 1 (the room-for-label rule goes). Today `episode_id_fault` refuses
    a run-id-grammar id of 205 bytes because no `-<label>` would fit under 206; the rule is now
    the UUID rule alone, so that id is refused for not being a UUID — and a UUID, the longest
    thing the rule admits, is admitted. Observed as: the sentence for the long id does not talk
    about room, the UUID gets `None`. RED at base: the long id's sentence says it leaves no room
    for a sibling."""
    from defender._run_id import episode_id_fault

    why = episode_id_fault("e" * 205)
    assert isinstance(why, str)
    assert "room" not in why, f"the episode id rule still counts room for a label: {why!r}"
    assert episode_id_fault(S.SAMPLE_UUID) is None


def _address_fields() -> dict[str, object]:
    from defender import _tenant
    from defender.run_repository import RunId

    return {"tenant_id": _tenant.TenantId(H.T_ID), "run_id": RunId.parse(S.SAMPLE_UUID)}


def test_1187_o2_run_address_admits_canonical_uuid_run_and_episode_ids():
    """#1187 declared change 1, positive control for the `RunAddress` refusals: an address built
    from canonical UUID text for its run id (as stored text) and its episode id keeps both, and
    the natural form (`episode_id=None`) builds too."""
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
    """#1187 declared change 1. `RunAddress(run_id=<stored text>)` refuses each non-canonical id
    at construction, so a bad curation row never reaches a lookup. (The run id is the stored
    text: a `RunId` object cannot be non-canonical.)"""
    from defender.run_repository import RunAddress

    err = S.raised(RunAddress, tenant_id=_address_fields()["tenant_id"], run_id=text,
                   episode_id=None)
    assert err is not None, f"RunAddress admitted the run id {text!r}"


@pytest.mark.parametrize("text", NON_CANONICAL)
def test_1187_o2_run_address_refuses_a_non_canonical_episode_id(text):
    """#1187 declared change 1. `RunAddress(episode_id=<text>)` refuses each non-canonical
    episode id, including the old `<id>-n<message>` shape the launcher used to derive."""
    from defender.run_repository import RunAddress

    err = S.raised(RunAddress, **_address_fields(), episode_id=text)
    assert err is not None, f"RunAddress admitted the episode id {text!r}"


def test_1187_o2_run_name_fault_still_tells_a_sidecar_from_a_run():
    """#1187 declared change 1 (guard: green at base, must stay green). The sidecar clause keeps
    working for UUID run names: `run_name_fault` answers `None` for a plain canonical UUID (a
    run) and a refusal for a UUID plus each known sidecar suffix, and for the staged shape a
    sidecar write creates first. The refusal's wording is not pinned: after #1187 such a name
    also fails the UUID rule, whichever clause speaks first."""
    from defender.run_repository import run_name_fault

    run_id = S.new_id()
    assert run_name_fault(run_id) is None, "a plain canonical UUID is a run"
    for suffix in S.SIDECAR_SUFFIXES:
        why = run_name_fault(run_id + suffix)
        assert why, f"{run_id + suffix!r} was admitted as a run name"
    staged = run_name_fault(f"{run_id}.run-end.json{H.STAGED_TAIL}")
    assert staged, "a staged sidecar was admitted as a run name"


def test_1187_o2_the_listing_takes_a_uuid_runs_sidecars_as_sidecars_not_as_runs(data_root):
    """#1187 declared change 1, the half `run_name_fault` cannot show (after #1187 a UUID plus a
    suffix is refused as a run name for two reasons at once, so its refusal does not say which
    clause spoke): in the real listing of `<T>/runs`, a UUID run folder with every known sidecar
    file beside it lists exactly that one run — each sidecar is taken as a sidecar of it, not
    refused as a stray and not listed as a run. No `_tenant.json` is planted (change 6). RED at
    base: the listing needs the container's record and refuses without it."""
    t = S.tenant(data_root)
    run_id = S.new_id()
    S.make_run(S.natural_runs(data_root, H.T_ID), run_id, sidecars=True)
    beside = sorted(p.name for p in S.natural_runs(data_root, H.T_ID).iterdir())
    assert beside == sorted([run_id, *(run_id + s for s in S.SIDECAR_SUFFIXES)]), beside

    listed = t.runs_repository().list()

    assert [str(r) for r in listed] == [run_id]


# ==========================================================================================
# O3 / declared change 4: the family gate no longer judges the composed `<episode>-<label>`.
# ==========================================================================================

#: A world label that is valid by its own rule (lower-case letters and digits, 200 bytes) but
#: would make `<36-byte uuid>-<label>` 237 bytes: over the 206-byte bound the gate used to apply
#: to the composed name. Far below NAME_MAX, so no filesystem rule is the reason it is refused.
LONG_LABEL = "w" * 200


def _family_doc_for(episode_id: str, *labels: str) -> dict:
    """The committed family document builder, rewritten to this episode id and to a control
    world `a` plus one world per label."""
    worlds = [T947.base_world()] + [T947.world_doc(label) for label in labels]
    return T947.family_doc(episode_id=episode_id, worlds=worlds)


def test_1187_o3_the_family_gate_does_not_refuse_a_label_for_a_long_composed_name():
    """#1187 declared change 4. Driven through the family model's two entry points
    (`parse_family`, which asks `_check_labels` per manifest, then `check_identities`, the gate
    run before anything launches): a UUID episode id with a world label of 200 valid characters
    loads and passes. Positive control through the same channel: a short label passes. RED at
    base: the gate refuses the label because `<episode_id>-<label>` is over the 206-byte bound."""
    from defender.runtime.branch import _family

    episode_id = S.new_id()
    short = _family.parse_family(_family_doc_for(episode_id, "b"))
    _family.check_identities(short)

    long_doc = _family_doc_for(episode_id, LONG_LABEL)
    family = _family.parse_family(long_doc)
    _family.check_identities(family)
    assert [w.world_id for w in family.worlds] == ["a", LONG_LABEL]


def test_1187_o3_a_label_is_still_held_to_its_own_rule():
    """#1187 declared change 4 (guard: green at base, must stay green). Dropping the composed-name
    check leaves the label's own rule: a label carrying `-` is refused (`-` delimits a view
    name, and the world-token alphabet has none) with the same UUID episode id for which `b`
    loads; the refusal names the label."""
    from defender.runtime.branch import _family

    episode_id = S.new_id()
    _family.parse_family(_family_doc_for(episode_id, "b"))
    err = S.raised(_family.parse_family, _family_doc_for(episode_id, "a-b"))
    assert S.is_a(err, _family.FamilyError), f"a label 'a-b' gave {err!r}"
    assert "a-b" in S.message(err), S.message(err)


def _attribute(obj: object, name: str) -> tuple[str, object]:
    """`("absent", None)`, `("raised", the exception)` or `("value", the value)` of
    `obj.<name>` — a property may be gone, refuse, or answer."""
    try:
        return "value", getattr(obj, name)
    except AttributeError:
        return "absent", None
    except Exception as exc:  # noqa: BLE001 — a property that refuses is an answer here
        return "raised", exc


def test_1187_o1_a_resumed_world_never_composes_its_arm_id(tmp_path):
    """#1187 census C1 row `ResumeWorld.run_id` (`runtime/branch/_family.py:713-715`): it
    "stops composing `<episode_id>-<label>`: it is deleted, or it is handed the roster's id" —
    the design admits both, so both pass. Through `resume_world_from(family, label, episode_dir,
    *, arm_ids=)` (the pinned spelling): handed the roster (`{label: RunId}`, as the sibling's
    view gives it), the world's `run_id`, if it still exists, IS the roster's id for its label;
    without the roster, `run_id` is gone, refuses, or answers anything but the composed
    `<episode_id>-<label>`. Adversary F1: no test read this value, so the composer survived
    behind a renamed helper (`_arm_name`) the census could not name. RED at base: `arm_ids` is
    not a keyword, and `run_id` composes."""
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
    """#1187 census C1 row `_episode_paths.py:390-399 EpisodeLayout.sibling_run_dir`
    (`runs/<ep>-<label>`, no production caller): deleted, with its lint entry. A deletion has
    no behaviour to drive, so this pin is introspection — on the layout class and its one
    instance; a RENAMED composer is the census's (local aliases resolved, adversary F1) and
    vulture's (a method with no caller)."""
    from defender import _episode_paths

    for owner in (_episode_paths.EpisodeLayout, _episode_paths.LAYOUT):
        assert not hasattr(owner, "sibling_run_dir"), (
            f"{owner!r} still spells the composed sibling run dir")


# ==========================================================================================
# O2: `run.py --run-id` refuses an old id and accepts a UUID.
# ==========================================================================================

def _run_py(tenant, alert: Path, run_id: str):
    """`run.main` over `--run-id run_id` with the spend seams recorded and nothing modelled or
    boxed (`SiblingRecorder`, `drive_run_py`): `(exit status, refusal, stderr, recorder)`."""
    rec = P.SiblingRecorder()
    argv = [str(alert), "--tenant", tenant.id, "--run-id", run_id, "--no-learn"]
    status, refusal, stderr = P.drive_run_py(argv, rec)
    return status, refusal, stderr, rec


def test_1187_o2_run_py_runs_a_pinned_uuid(tmp_path, data_root):
    """#1187 declared change 1, positive control for the `--run-id` refusals: `--run-id <uuid>`
    runs — the lifecycle seam is reached once and the run folder `<T>/runs/<uuid>` exists. (A
    green guard at base too: today's grammar admits a UUID.)"""
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
    """#1187 declared change 1. `run.py --run-id <old id>` exits with a refusal that names the
    run id (a `sys.exit(str)`), before the lifecycle runs and before any run folder exists:
    the old pinned slug `live-lever-up-20260930-sudo`, the old minted shape, an upper-case UUID,
    braces, no hyphens, `urn:`, a suffixed UUID and `latest`. (Ids with surrounding whitespace
    and the empty id are driven at `RunId.parse`; argv carries them badly.) RED at base for the
    ones today's grammar admits."""
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


# ==========================================================================================
# O1: the census. No production source composes, derives or bounds an id by meaning.
# ==========================================================================================

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
    """Every site under `root` (the `defender/` folder, or a planted tree) that reads meaning
    out of an id, from the AST of each production file:

    * `fstring`: an f-string where a replacement field naming `episode_id` is followed at once
      by a literal `-` — `f"{episode_id}-{label}"`, `f"{self.family.episode_id}-x"`, `-r{n}`.
      Matched on the f-string's own parts rather than a regex over text, so a `-` after a space
      or a closing quote inside a message is not confused with a join.
    * `ref`: a use of a banned function, or of the banned constant, as a call or a value — a
      name resolved through `_astlib` (an alias, a module attribute, an import from anywhere
      resolve to their origin; the module's own `def` is reached through `own_defs`).
    * `def`: the bound's constant being defined.
    * `str`: a banned name as a string constant, i.e. an `__all__` entry re-exporting it.
    * `mint-args`: `RunId.mint(...)` called with an argument (a label or a clock).
    * `composer`: a call to a function that joins one of its PARAMETERS to a `-` (found over every
      file, matched by bare name), handing it an expression that spells `episode_id` —
      `compose(family.episode_id, label)` (adversary F1, round 2). Limits, said plainly: the
      callee is matched by name, not resolved to one definition; an id reaching the call
      through a container, `*args`, a lambda default or another module's constant is not
      followed. `self._eid = episode_id` joined in another method IS followed (attributes are
      tracked file-wide by name, not per class).
    * `concat`: the same join spelled without an f-string (review F13) — `<episode_id> + "-..."`,
      `"-".join([... episode_id ...])`, `"{}-{}".format(episode_id, ...)` and
      `"%s-%s" % (episode_id, ...)`.

    The listing is `_astlib.source_files`: git's tracked files plus untracked, unignored ones,
    so it covers the brief's "tracked `.py` under `defender/`" and also a new module not yet
    committed. `tests/` is dropped by name (`skip_tests`)."""
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
    """`{position: name}` of the parameters of `func` that an f-string field or a `+` joins to a
    `-` in its body, directly or through a local alias — a function that COMPOSES from what it
    is handed (adversary F1, round 2: `compose(eid, label)` spells no `episode_id`; the caller
    does)."""
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
        for index, name in enumerate(args):
            if index or name not in ("self", "cls"):
                if any(reaches(f, name) for f in fields):
                    out[index - (1 if args[:1] in (["self"], ["cls"]) else 0)] = name
    return out


def _composers(trees: list[ast.Module]) -> dict[str, dict[int, str]]:
    """`{function or method name: {call position: parameter}}` over every file: the functions
    `_joined_params` finds. Matched by bare name at the call (a cross-module call cannot be
    resolved to one definition here), which is why a hit needs an `episode_id` argument too."""
    out: dict[str, dict[int, str]] = {}
    for tree in trees:
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and (
                    joined := _joined_params(node)):
                out.setdefault(node.name, {}).update(joined)
    return out


def _composer_calls(node: ast.AST, rel: str, values: dict,
                    composers: dict[str, dict[int, str]]) -> list[Hit]:
    """`composer` hits: a call to a composing function whose joined parameter is handed an
    expression that spells `episode_id` (directly, or through a local or attribute alias)."""
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
    """Does `node` spell `episode_id` — directly, or through a local name its scope bound to
    something that does (`ep = episode_id`, `eid = self.family.episode_id`; adversary F1)?"""
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
    """`fstring` hits: a replacement field naming `episode_id` (directly or through a local
    alias) followed at once by a `-`."""
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
    """`ref` hits (a banned function or the constant used, however it is reached) and the
    constant's `def`."""
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
    """`mint-args` hits: `RunId.mint(...)` called with a label or a clock — spelled directly,
    or reached as `getattr(RunId, "mint")(...)` (adversary F1)."""
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
    """#1187 O1 and declared changes 1, 2, 4: production source (every `.py` under `defender/`
    but `tests/`) has no f-string joining an `episode_id` to a `-`, no call to `mint_run_id`,
    `episode_id_for`, `_claimed_slug` or `arm_run_id_for`, no `RunId.mint(<label>)`, and no
    `RUN_ID_MAX_BYTES`. RED at base (29 sites in all, composer calls included): the hits are the design's census C1 rows (the stamp-label
    minter and its one caller, the `-n<message>` deriver and its `-r<n>` retry, the folder-name
    slug matcher, the composed sibling names in the family gate, the judge, the record writer
    and the episode layout, and #1257's arm-id composer)."""
    hits = census(DEFENDER)
    listing = "\n  ".join(str(h) for h in hits)
    assert hits == [], f"{len(hits)} production sites still read or build id meaning:\n  {listing}"


def test_1187_o1_the_census_finds_what_it_is_meant_to_find(tmp_path):
    """Positive control for the census, through the same scanner and listing it runs on
    production: a planted file carrying each shape is reported, shape by shape, with the alias,
    the attribute form and the module's own function all resolved — and each join made through
    a LOCAL alias of the episode id (adversary F1: `ep = episode_id; f"{ep}-{label}"` kept
    every composer while the census read []), the mint reached through `getattr`, an id passed as an argument to a function that composes
    from its parameter, and an id stored on `self` and joined in another method. A clean
    file beside it is not: a name bound to the episode id in one function and a same-named
    local bound to a label in another are told apart. Without this, a scanner that matched
    nothing would pass the census above."""
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
    """The census is over production source: the same dirty shape under a `tests/` folder is not
    reported (and is, with `skip_tests=False`), so the contract's own fixtures and the tests that
    pin the old behaviour do not fail it."""
    root = tmp_path / "planted"
    (root / "tests").mkdir(parents=True)
    (root / "tests" / "old.py").write_text(
        "def f(episode_id, label):\n    return f'{episode_id}-{label}'\n", encoding="utf-8")

    assert census(root) == []
    assert [h.kind for h in census(root, skip_tests=False)] == ["fstring"]

