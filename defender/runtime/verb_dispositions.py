"""The verb-disposition table — the one authored answer to "who may call what".

WHY THIS EXISTS (#995). The gather grant used to be a tuple of `(system, verb)` pairs in
`driver/_build.py`, and the judge's a second tuple in another package. A pair not listed was
not granted, so a newly connected system was reachable only if a human remembered to edit a
file that `/connect`'s own lane rules forbid it to touch — and the failure was not even a
denial. A real, declared verb on an ungranted system came back `UNDECLARED`, wording
identical to a typo's, so the symptom pointed at a spelling mistake in an adapter that was
correct.

WHAT IS DERIVED AND WHAT IS AUTHORED — the whole design is this line.

  DERIVED, by walking:  which systems exist, which verbs each declares, what params each takes.
  AUTHORED, by a human: which of those any role may call.

Deriving the second from the first is the one repair that must never be made: it would mean
an adapter file appearing on disk grants itself read access to the estate. `verb_grant.py`
says the same thing about the type this module produces — "authored data, not a filter
derived from the registry" — and nothing here weakens it. `grant_for` reads the table and
only the table; it never touches the filesystem, and `test_the_grant_is_not_a_function_of_
what_is_on_disk` is the probe that keeps it honest.

What #995 derives instead is the OBLIGATION TO DECIDE. `census_gaps` compares the walked
census against the table and reports residue in both directions, so a new system cannot be
silently ungranted — only ungranted on the record, with a reason a reviewer can read. That is
strictly stronger than the old property: before, a new system was ungranted by accident.

WHY A CONFIG FILE RATHER THAN A PYTHON LITERAL. The table is this deployment's answer about
this deployment's systems, so it lives in the environment tree as data. Two consequences that
are features: the shipped runtime stops carrying vendor names, and a product with no table
grants nothing. The second is only safe because `load_dispositions` REFUSES an absent or
empty table rather than returning one — every refusal below is a raise.

WHY NO `verb_class` FIELD. Every shipped verb is read-class and the projection hardcodes `r`.
That is deliberate under-expression: a write grant should cost a schema change and its own
review, not a one-word edit to a data file. Adding `rw` here later is a change to this
module, which is the friction that decision deserves.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

import yaml

from defender import _yaml
from defender.runtime.agent_role import AgentRole
from defender.runtime.verb_grant import VerbGrant
from defender.runtime.verbs import is_system_name

#: Repo-relative home of the table. In the environment tree, not the runtime package: it is
#: per-deployment data, and `lint_shippable_surface` already treats that tree as the place
#: vendor names legitimately live.
DISPOSITIONS_REL = "defender/knowledge/environment/verb-grants.yaml"

#: The roles a row may name. Sourced from `AgentRole` rather than respelled, so a role that is
#: renamed cannot leave a table silently granting to a name nothing answers to.
KNOWN_ROLES: frozenset[str] = frozenset({AgentRole.GATHER.value, AgentRole.JUDGE.value})

#: Every shipped disposition is read-class. See the module docstring for why this is not a
#: field in the file.
READ_CLASS = "r"


class DispositionError(Exception):
    """Raised for any table this module will not stand behind.

    One exception for every failure — absent file, unparseable text, unknown role, reasonless
    withholding — because every one of them has the same correct handling at startup: stop.
    A table that half-loaded is the deny-all-by-accident state #995 exists to make
    unreachable, so there is no partial-success path to distinguish.
    """


@dataclass(frozen=True)
class Disposition:
    """One `(system, verb)` and the roles allowed to call it.

    `roles` empty means granted to nobody, which is a DECISION and therefore requires
    `reason`. It is not the same as the pair being absent from the table — absence is residue
    and `census_gaps` reports it. Keeping those two apart is the point of the whole file.
    """

    system: str
    verb: str
    roles: frozenset[str]
    reason: str | None = None

    @property
    def pair(self) -> tuple[str, str]:
        return (self.system, self.verb)


@dataclass(frozen=True)
class CensusGaps:
    """Residue between the walked census and the table, in both directions.

    Three fields rather than one list of findings: they have different remedies. `undecided`
    means a human must decide something; `phantom` means a row outlived its verb; `unreasoned`
    means a decision was made without saying why.
    """

    undecided: tuple[tuple[str, str], ...] = ()
    phantom: tuple[tuple[str, str], ...] = ()
    unreasoned: tuple[tuple[str, str], ...] = ()

    def __bool__(self) -> bool:
        return bool(self.undecided or self.phantom or self.unreasoned)


def dispositions_path(defender_dir: Path) -> Path:
    """The table's path inside an ARBITRARY defender tree.

    Takes the tree rather than reading a module-level constant, for the same reason
    `_paths.adapters_under` does: the lint gate resolves the table of a repo it was pointed
    at, which is not the tree this process is running from.
    """
    return Path(defender_dir) / "knowledge" / "environment" / "verb-grants.yaml"


def _systems_block(path: Path) -> Mapping[object, object]:
    """Read the file and return its `dispositions:` mapping, or raise.

    Split out from `load_dispositions` so that function stays one job — turning rows into
    `Disposition`s — rather than two. Everything here is about the FILE being trustworthy at
    all; everything there is about a row being well formed.
    """
    if not path.is_file():
        raise DispositionError(f"verb-disposition table not found at {path}")
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as e:
        raise DispositionError(f"verb-disposition table at {path} is unreadable ({e})") from e

    # Duplicate keys BEFORE the load, because the load is where they disappear. Two rows for
    # one pair is the same defect this issue is about — two statements, one silently honoured.
    duplicates = _yaml.duplicate_key_paths(text)
    if duplicates:
        raise DispositionError(
            f"verb-disposition table at {path} repeats key(s) {list(duplicates)} — YAML "
            "would silently honour the last of each; write one row per pair"
        )

    try:
        data = _yaml.safe_load(text)
    except yaml.YAMLError as e:
        raise DispositionError(f"verb-disposition table at {path} does not parse ({e})") from e

    if not isinstance(data, Mapping):
        raise DispositionError(
            f"verb-disposition table at {path} must be a mapping with a `dispositions:` key"
        )
    systems = data.get("dispositions")
    if not isinstance(systems, Mapping) or not systems:
        raise DispositionError(
            f"verb-disposition table at {path} declares no dispositions. An empty table is "
            "not a deny-all — it is indistinguishable from a table that failed to load, "
            "which is the silent-mute failure this file exists to prevent. Grant nothing by "
            "writing rows with `roles: []` and a reason."
        )
    return systems


def load_dispositions(path: Path) -> tuple[Disposition, ...]:
    """Parse and VALIDATE the table at `path`. Raises `DispositionError` on anything doubtful.

    Every refusal names the offending system or pair. That is not politeness: the failure is
    read at startup by someone who has just connected a system, and "invalid table" sends them
    back to bisect a file by hand.

    The validation is deliberately total rather than best-effort. A permission table that
    loaded 90% of its rows would grant a coherent-looking subset, and the missing 10% would
    present exactly as this issue's original symptom.
    """
    path = Path(path)
    systems = _systems_block(path)
    rows: list[Disposition] = []
    for system, verbs in sorted(systems.items(), key=lambda kv: str(kv[0])):
        if not isinstance(system, str) or not is_system_name(system):
            raise DispositionError(f"{path}: {system!r} is not a well-formed system name")
        if not isinstance(verbs, Mapping) or not verbs:
            raise DispositionError(f"{path}: system {system!r} carries no verb rows")
        for verb_name, body in sorted(verbs.items(), key=lambda kv: str(kv[0])):
            rows.append(_disposition_row(path, system, verb_name, body))
    return tuple(rows)


def _disposition_row(
    path: Path, system: str, verb_name: object, body: object
) -> Disposition:
    where = f"{path}: {system}.{verb_name}"
    if not isinstance(verb_name, str) or not verb_name:
        raise DispositionError(f"{where} is not a verb name")
    if not isinstance(body, Mapping):
        raise DispositionError(f"{where} must be a mapping with a `roles:` key")

    # An ABSENT `roles` is an unfinished row, not a withholding. Defaulting it to `[]` would
    # make a half-written table withhold silently — the same class as everything else here.
    if "roles" not in body:
        raise DispositionError(f"{where} has no `roles:` key")
    raw_roles = body["roles"]
    if not isinstance(raw_roles, list):
        raise DispositionError(f"{where}: `roles` must be a list")
    roles: list[str] = []
    for role in raw_roles:
        if not isinstance(role, str) or role not in KNOWN_ROLES:
            raise DispositionError(f"{where}: {role!r} is not a role ({sorted(KNOWN_ROLES)})")
        roles.append(role)
    if len(set(roles)) != len(roles):
        raise DispositionError(f"{where}: `roles` repeats a role")

    reason = body.get("reason")
    if reason is not None and not isinstance(reason, str):
        raise DispositionError(f"{where}: `reason` must be text")
    if not roles and not (reason or "").strip():
        # `.strip()`, not truthiness: `reason: ""` and `reason: "   "` both satisfy a presence
        # check while recording nothing, and this field's only job is to be read by a human.
        raise DispositionError(
            f"{where} is granted to nobody and gives no reason. A residue entry that costs "
            "nothing to add is a free way to silence the census gate — say why."
        )
    return Disposition(
        system=system, verb=verb_name, roles=frozenset(roles), reason=reason,
    )


def grant_for(role: str, dispositions: tuple[Disposition, ...]) -> VerbGrant:
    """Project the table onto one role's `VerbGrant`.

    Reads the table and NOTHING else — no filesystem, no registry. That is the property
    keeping a dropped-in adapter from granting itself, and it is why this function takes the
    parsed rows rather than a path it could be tempted to walk beside.

    A role no row names yields an empty grant, because this is a filter and nothing matched —
    not a fallback, and not a judgement that the role should hold nothing. A MISSPELLED role is
    caught earlier, by `load_dispositions`, the only place that can tell a typo from a role
    that legitimately appears in no row.

    Do NOT read that empty return as the mechanism behind the adversarial judge's empty grant:
    that stage is handed `DENY_ALL` explicitly by `_run_judge_pydantic` and never reaches here.
    """
    entries = tuple(
        (d.system, d.verb, READ_CLASS)
        for d in dispositions
        if role in d.roles
    )
    return VerbGrant(role=role, entries=entries)


def census_gaps(
    walked: Mapping[str, frozenset[str]], dispositions: tuple[Disposition, ...]
) -> CensusGaps:
    """Residue between what the tree declares and what the table decides.

    PURE, and takes `walked` as an argument rather than resolving it. Resolving the census
    reads the committed tree through git, and this module is imported while the runtime builds
    its agent definitions — where a git subprocess has no business running. The gate that
    supplies `walked` is a CI script, which is the right place for it.

    Both directions are reported. `undecided` is the reported defect: a verb the tree declares
    and the table ignores, which today means silently ungranted. `phantom` is its mirror: a row
    for a verb no adapter declares any more, which would otherwise surface much later as a
    startup failure when the registry cross-checks the grant.
    """
    decided = {d.pair for d in dispositions}
    declared = {(system, verb) for system, verbs in walked.items() for verb in verbs}
    return CensusGaps(
        undecided=tuple(sorted(declared - decided)),
        phantom=tuple(sorted(decided - declared)),
        unreasoned=tuple(sorted(
            d.pair for d in dispositions if not d.roles and not (d.reason or "").strip()
        )),
    )


__all__ = [
    "DISPOSITIONS_REL",
    "KNOWN_ROLES",
    "CensusGaps",
    "Disposition",
    "DispositionError",
    "census_gaps",
    "dispositions_path",
    "grant_for",
    "load_dispositions",
]
