"""#986 M4 — the GOVERNANCE RE-ASK ORACLE, the mechanical measure O1 is scored with.

O1: when a lead resolves the machine the alerted privileged action actually ran on, the run
asks the governance systems about *that* machine before it closes. The design settles the
measurement rather than leaving it to a reader:

    a run passes when some row of `executed_queries.jsonl` whose `system` is one of
    `cmdb`, `change-mgmt`, `identity`, `ticket` carries the resolved name among its
    `params` VALUES.

Baseline on the nine runs the owner has on disk: 0/9 for `db-1`, while `soc-playground`
appears 5-11 times per run (census C4). That pairing — governance WAS asked, about the wrong
machine — is the shape this oracle has to separate, and it is the shape a lazy implementation
(grep the whole row for the string) gets wrong in the safe-looking direction.

WHY EVERY FIXTURE IS BUILT HERE AND NONE IS READ FROM DISK. `.defender-runs/` is gitignored
and does not exist in a fresh checkout, so the nine runs are NOT available as checked-in
fixtures and no test may depend on them. Each test below writes its own run dir under
`tmp_path`, by hand, in the row shape a real run emits. `_row`'s default cells are copied
from a real `executed_queries.jsonl` line, including the fact that `params` values are not
all strings (`limit` is an int) — the one detail that decides several tests here.

THE SPEC THIS FILE PINS, for the implementer:

    defender/scripts/governance_reask.py
        GOVERNANCE_SYSTEMS: frozenset[str]                          # the four, and only those
        def asked_governance_about(run_dir: Path, name: str) -> bool

`asked_governance_about` is imported INSIDE each test body, never at module scope, so this
file still COLLECTS on a tree where the module does not exist. Red is the expected state of a
spec; an uncollectable file is not.

FOUR QUESTIONS THE DESIGN DOC DOES NOT SETTLE. Each is decided here, pinned by a test, and
listed in the write-tests report as an assumption rather than as a derivation:

  1. WHOLE-VALUE, never substring. `db-1` does not match a params value `db-11` or
     `prod-db-1-replica`. A substring rule scores "asked about db-11" as "asked about db-1",
     which is precisely the coarse/fine confusion #986 exists to refuse.
  2. CASE-INSENSITIVE. A CMDB that answers `DB-1` was asked about `db-1`; hostnames are not
     case-distinguishing, and no two machines in the estate differ only in case.
  3. A params KEY is not a params value. `{"db-1": "lookup"}` is not an ask about `db-1`.
  4. STRING leaves only, and nested containers are walked. `{"hosts": ["db-1"]}` and
     `{"filter": {"host": "db-1"}}` are asks; `{"limit": 1}` is never an ask about the machine
     named `1`, because coercing an int into the comparison buys nothing and costs a false
     positive on every paginated query in the log.

NOT AN OBLIGATION HERE, from the design's own list: the oracle's known miss (t4 asked identity
about users read out of the container's CMDB record, which does not count) is accepted, not
worked around. Nothing below tries to widen the oracle to catch it.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

DEFENDER = Path(__file__).resolve().parents[1]
if str(DEFENDER.parent) not in sys.path:  # pragma: no cover - import bootstrap
    sys.path.insert(0, str(DEFENDER.parent))


# drivers


def _asked(run_dir: Path, name: str) -> bool:
    """The checker's public entry point. Imported inside the body — see the module docstring."""
    from defender.scripts.governance_reask import asked_governance_about

    return asked_governance_about(run_dir, name)


def _row(system: str, params: object, *, lead_id: str = "l-000", **cells: object) -> str:
    """One `executed_queries.jsonl` line, in the shape a real run writes.

    The non-`params` cells are a real row's, verbatim in kind: a `raw_command` that spells the
    query out in a shell string, a `query_id`, a `payload_path`. They are here because they
    are where a whole-row string search finds the name it must not find.
    """
    row: dict = {
        "lead_id": lead_id,
        "seq": 0,
        "system": system,
        "verb": "get-host",
        "query_id": f"{system}.get-host",
        "params": params,
        "raw_command": f"{system} get-host",
        "payload_path": f"gather_raw/{lead_id}.json",
        "exit_code": 0,
        "error_class": None,
        "payload_status": "ok",
    }
    row.update(cells)
    return json.dumps(row)


def _run(tmp_path: Path, *lines: str, name: str = "run") -> Path:
    """A run dir carrying exactly these physical lines as its query log.

    Written by hand rather than through `append_jsonl`, because half the faults this file
    drives the checker through — a torn last line above all — are not lines the appender can
    produce. Fixture JSONL written by hand is the sanctioned test-side spelling; production
    reads still go through `defender._io.read_jsonl_rows`.
    """
    run = tmp_path / name
    run.mkdir(parents=True, exist_ok=True)
    (run / "executed_queries.jsonl").write_text("".join(f"{ln}\n" for ln in lines), encoding="utf-8")
    return run


#: The four systems the design names, and four that must not count. `threat-intel` is on the
#: negative side deliberately: `evals/oracle_golden/audit_judge.py:62` ships a nearby-looking
#: `STATE_SYSTEMS` frozenset that INCLUDES `threat-intel` and OMITS `ticket`, and an
#: implementer who reaches for that set instead of writing this one gets both ends wrong.
GOVERNANCE = ("cmdb", "change-mgmt", "identity", "ticket")
NOT_GOVERNANCE = ("elastic", "threat-intel", "host-state", "edr")


# the oracle's two sides


def test_a_governance_query_carrying_the_name_as_a_param_is_the_oracles_true(tmp_path):
    """CLAIM: the design's own worked positive — a synthetic `cmdb get-host host=db-1` row —
    reads as an ask about `db-1`.

    The floor of the whole file. Every negative below is worthless without it: a checker that
    returned `False` unconditionally would satisfy the baseline test, the substring test, the
    raw-command test and the malformed-row tests all at once."""
    run = _run(tmp_path, _row("cmdb", {"host": "db-1"}))
    assert _asked(run, "db-1") is True, "a cmdb row with host=db-1 is the oracle's worked example"


def test_the_baseline_shape_asked_governance_about_the_wrong_machine(tmp_path):
    """CLAIM: a run that queried all four governance systems about the ALERT-ENVELOPE host and
    never about the resolved container reads False for the container and True for the host.

    THE headline discriminator, and the census the oracle was defined to reproduce (C4: 0/9 for
    `db-1`; `soc-playground` 5-11 times per run). The fixture is not "a run with no governance
    rows" — that shape would let `return False` pass. It is the baseline's actual shape: the
    governance systems WERE asked, repeatedly, about `soc-playground`, while `db-1` is present
    in the run only as an elastic/host-state parameter, which is exactly how the container's
    name reached the record without ever reaching a governance system.

    The nine real runs are not checked in (`.defender-runs/` is gitignored), so this is their
    shape rebuilt by hand rather than a replay of them."""
    run = _run(
        tmp_path,
        _row("cmdb", {"host": "soc-playground"}, lead_id="l-002"),
        _row("change-mgmt", {"ci_name": "soc-playground", "window": "24h"}, lead_id="l-003"),
        _row("identity", {"host": "soc-playground", "user": "root"}, lead_id="l-004"),
        _row("ticket", {"ci": "soc-playground"}, lead_id="l-005"),
        # where `db-1` actually shows up in the baseline: the leads that resolved it.
        _row("elastic", {"native_query": "container.name:db-1", "limit": 1}, lead_id="l-006"),
        _row("host-state", {"target": "db-1", "check": "proc-tree"}, lead_id="l-007"),
    )
    assert _asked(run, "db-1") is False, (
        "the container was never put to a governance system — an elastic or host-state row "
        "naming it is the run learning the name, not the run asking about it"
    )
    assert _asked(run, "soc-playground") is True, (
        "positive control on the same fixture: governance WAS asked, about the coarse subject"
    )


def test_only_the_four_governance_systems_count(tmp_path):
    """CLAIM: system membership is per-row and per-system, over the design's four names.

    Eight run dirs, each holding ONE row that carries `db-1` as a param and differs only in
    `system`. Split across fixtures rather than gathered into one, because one fixture yields
    one boolean and could not tell "all four count" from "any row counts"."""
    for system in GOVERNANCE:
        run = _run(tmp_path, _row(system, {"host": "db-1"}), name=f"yes-{system}")
        assert _asked(run, "db-1") is True, f"{system} is a governance system and must count"
    for system in NOT_GOVERNANCE:
        run = _run(tmp_path, _row(system, {"host": "db-1"}), name=f"no-{system}")
        assert _asked(run, "db-1") is False, (
            f"{system} carried the name as a param and must NOT count — the oracle measures "
            "whether GOVERNANCE was re-asked, not whether the name was ever queried"
        )


# false positives — where a lazy implementation passes everything above


def test_the_name_in_a_raw_command_but_not_in_params_is_not_an_ask(tmp_path):
    """CLAIM: the oracle reads `params` values, not the row.

    `json.dumps(row)` and grep is the shortest implementation that passes every positive test
    in this file, and it is wrong: `raw_command`, `query_id` and `payload_path` all carry
    query text, and a run whose CMDB call was `cmdb get-host --host soc-playground` while its
    shell line happened to mention the container would score as an ask it never made. The
    paired positive on the same fixture is the parameter the row really carried."""
    run = _run(
        tmp_path,
        _row(
            "cmdb",
            {"host": "soc-playground"},
            raw_command="cmdb get-host --host soc-playground  # container db-1",
            query_id="cmdb.get-host.db-1",
            payload_path="gather_raw/db-1.json",
        ),
    )
    assert _asked(run, "db-1") is False, (
        "the name appears three times in this row and never once as a params VALUE"
    )
    assert _asked(run, "soc-playground") is True, "positive control: the param the row carried"


def test_a_params_value_matches_whole_and_never_by_substring(tmp_path):
    """CLAIM (assumption — the design does not settle it): the comparison is whole-value.

    A substring rule turns "asked CMDB about db-11" and "asked about the replica of db-1" into
    "asked about db-1", which is the coarse/fine confusion this issue exists to refuse, wearing
    a different hat. The paired positives are the names those rows DID ask about."""
    run = _run(
        tmp_path,
        _row("cmdb", {"host": "db-11"}, lead_id="l-002"),
        _row("identity", {"host": "prod-db-1-replica"}, lead_id="l-003"),
    )
    assert _asked(run, "db-1") is False, (
        "`db-1` is a substring of both params values and the subject of neither"
    )
    assert _asked(run, "db-11") is True, "positive control: the name that row actually carried"
    assert _asked(run, "prod-db-1-replica") is True, "positive control on the second row"


def test_the_name_matches_a_params_value_case_insensitively(tmp_path):
    """CLAIM (assumption — the design does not settle it): the comparison folds case.

    A CMDB record spelled `DB-1` is the same machine; hostnames do not distinguish case, and
    an oracle that scored a real re-ask as a miss because the CI record shouts would understate
    the very rate the experiment is measuring. Paired with a name the row does NOT carry, so
    the test cannot pass by matching everything."""
    run = _run(tmp_path, _row("cmdb", {"host": "DB-1"}))
    assert _asked(run, "db-1") is True, "`DB-1` and `db-1` are one machine"
    assert _asked(run, "web-1") is False, "negative control: a name this row does not carry"


def test_both_the_subject_and_the_value_are_trimmed_before_comparison(tmp_path):
    """CLAIM (a FIFTH assumption, undeclared until now): both sides are `.strip()`ed.

    NEITHER STRIP WAS PINNED. Removing both — `name.casefold()` and `value.casefold()` — left
    every other test in this file green, because `test_an_empty_name_is_never_an_ask`'s `"   "`
    case passes either way (an untrimmed `"   "` simply matches no value) and every other
    fixture is spelled without padding. So the module's own claim that a name "that trimmed to
    nothing" is refused rested on an assertion that could not fail.

    The two halves are deliberate and pull in opposite-looking directions. A NAME read out of a
    record cell can carry padding the record's formatting put there, and scoring that as a miss
    would understate the rate — the case-fold argument, one character class over. A VALUE's
    padding is the same fact about the same machine, so `"db-1 "` in a params cell IS an ask
    about `db-1` — which widens the file's "WHOLE-VALUE, never substring" rule by exactly that
    character class, and is written down here for that reason rather than left in the code."""
    run = _run(tmp_path, _row("cmdb", {"host": " db-1 "}, lead_id="l-002"))
    assert _asked(run, "db-1") is True, "a padded params VALUE names the same machine"
    assert _asked(run, " db-1 ") is True, "a padded NAME names the same machine"
    assert _asked(run, "db") is False, (
        "negative control: trimming must not become substring matching"
    )


def test_a_params_key_is_not_a_params_value(tmp_path):
    """CLAIM (assumption — the design does not settle it): keys do not count, values do.

    The design says "among its `params` values", and a mapping walked carelessly (`name in
    json.dumps(params)`, or a walk that visits keys) reads a parameter NAMED for the machine as
    a question ABOUT it."""
    run = _run(tmp_path, _row("cmdb", {"db-1": "lookup", "host": "soc-playground"}))
    assert _asked(run, "db-1") is False, "`db-1` is the key here, not the value"
    assert _asked(run, "soc-playground") is True, "positive control: the value on the same row"


def test_a_non_string_params_value_is_never_the_resolved_name(tmp_path):
    """CLAIM (assumption — the design does not settle it): only string leaves are compared.

    `params` values are not all strings — `limit` is an int in every real elastic row and in
    plenty of governance ones — so a checker that stringifies every leaf answers True for the
    machine named `1` on any paginated governance query. A resolved machine name arrives as a
    string; nothing is lost by refusing the coercion."""
    run = _run(tmp_path, _row("cmdb", {"limit": 1, "page": True, "host": "db-1"}))
    assert _asked(run, "1") is False, "`limit=1` is not an ask about a machine named `1`"
    assert _asked(run, "True") is False, "nor is a boolean cell an ask about `True`"
    assert _asked(run, "db-1") is True, "positive control: the string value on the same row"


def test_a_name_nested_inside_a_params_list_or_object_still_counts(tmp_path):
    """CLAIM (assumption — the design does not settle it): the walk recurses into containers.

    A governance query that filters on a list of CIs, or carries a structured filter object, is
    asking about every host it names. Reading only the top level would score those runs as
    misses. Recursion is bounded by the same whole-value, string-only rule as the flat case, so
    it widens what counts as a VALUE and never what counts as a MATCH."""
    run = _run(
        tmp_path,
        _row("change-mgmt", {"cis": ["web-2", "db-1"]}, lead_id="l-002"),
        _row("identity", {"filter": {"scope": {"host": "app-3"}}}, lead_id="l-003"),
    )
    assert _asked(run, "db-1") is True, "a name in a params list is a name among the params"
    assert _asked(run, "app-3") is True, "and so is one in a nested params object"
    assert _asked(run, "db-2") is False, (
        "negative control: recursion must not turn the walk into a match-anything"
    )


def test_an_empty_name_is_never_an_ask(tmp_path):
    """CLAIM: a degenerate name answers False rather than matching every row.

    An oracle called with an unresolved name — the caller's own `""`, or a name that trimmed to
    nothing — must not report that governance was asked. This is the single cheapest way for a
    live-trial harness to read 12/12 without a single re-ask having happened."""
    run = _run(tmp_path, _row("cmdb", {"host": "db-1", "note": ""}))
    assert _asked(run, "") is False, "an empty name matched a row"
    assert _asked(run, "   ") is False, "a whitespace-only name matched a row"
    assert _asked(run, "db-1") is True, "positive control: the fixture does answer True"


# real faults through the real primitive


def test_a_torn_last_line_loses_only_its_own_row(tmp_path):
    """CLAIM: the log is read tolerantly — an unparseable physical line is skipped, the intact
    rows around it still answer, and nothing raises.

    A run dir is a live tree an agent is writing into; `defender._io.read_jsonl_rows` exists
    precisely because the last line of an appended JSONL can be torn (`lint_unsafe_jsonl_io`,
    #446). The first fixture proves the intact rows survive the tear. The SECOND is the half a
    tolerant reader gets wrong in the other direction: when the torn line is the one that would
    have named the container, its bytes are not evidence, and a checker that fell back to a
    raw-text search of the file would count them."""
    survives = _run(
        tmp_path,
        _row("cmdb", {"host": "soc-playground"}, lead_id="l-002"),
        _row("cmdb", {"host": "db-1"}, lead_id="l-003"),
        '{"lead_id": "l-004", "seq": 3, "system": "cmd',
        name="torn-tail",
    )
    assert _asked(survives, "db-1") is True, (
        "a torn last line swallowed the intact rows before it"
    )

    only_torn = _run(
        tmp_path,
        _row("cmdb", {"host": "soc-playground"}, lead_id="l-002"),
        '{"lead_id": "l-003", "seq": 2, "system": "cmdb", "params": {"host": "db-1"',
        name="torn-evidence",
    )
    assert _asked(only_torn, "db-1") is False, (
        "the only line naming the container never parsed — its bytes are not a row"
    )
    assert _asked(only_torn, "soc-playground") is True, (
        "positive control on the same fixture: the intact row still answers"
    )


def test_a_run_with_no_query_log_answers_false_rather_than_raising(tmp_path):
    """CLAIM: an absent (or absent-dir) query log is a False, not an exception.

    The oracle is run over a directory of runs, and a run that died before its first gather
    writes no log at all. The positive control is the SAME run dir once the log exists, so the
    False cannot be a checker that always answers False for this path."""
    empty = tmp_path / "no-log"
    empty.mkdir()
    assert _asked(empty, "db-1") is False, "a run dir with no query log must answer False"

    missing = tmp_path / "not-a-run"
    assert _asked(missing, "db-1") is False, "a run dir that does not exist must answer False"

    (empty / "executed_queries.jsonl").write_text(_row("cmdb", {"host": "db-1"}) + "\n",
                                                  encoding="utf-8")
    assert _asked(empty, "db-1") is True, (
        "positive control on the same path: the log appeared and the answer moved"
    )


def test_a_malformed_row_is_skipped_and_never_counts_as_an_ask(tmp_path):
    """CLAIM: rows the shape contract does not fit are skipped, and skipping them neither
    raises nor hides the rows after them.

    Four real degeneracies, in one fixture, ahead of one good row: no `params` key at all, a
    null `params`, a `params` that is a bare string (not a mapping, so it has no values —
    assumption, flagged), and a row with no `system`. The good row is last, so an
    implementation that stops walking at the first surprise fails."""
    run = _run(
        tmp_path,
        _row("cmdb", None, lead_id="l-002"),
        json.dumps({"lead_id": "l-003", "seq": 2, "system": "cmdb"}),  # no params key
        _row("cmdb", "db-1", lead_id="l-004"),                          # params is not a mapping
        json.dumps({"lead_id": "l-005", "seq": 4, "params": {"host": "db-1"}}),  # no system
        _row("identity", {"host": "soc-playground"}, lead_id="l-006"),
    )
    assert _asked(run, "db-1") is False, (
        "no well-formed governance row carries `db-1` as a params value — a bare-string "
        "`params`, and a row with no `system` cell, are malformed telemetry, not asks"
    )
    assert _asked(run, "soc-playground") is True, (
        "positive control: the well-formed row AFTER all four degeneracies still answers"
    )


# ADVERSARY-CLOSED (#986 red-team pass). Each test below closes a hole where an
# implementation greened the suite above while violating a claim this file already made.


def test_the_exported_vocabulary_is_the_designs_four_and_only_those():
    """CLAIM: `GOVERNANCE_SYSTEMS` IS the design's set — asserted on the symbol, not inferred
    from behaviour.

    The module docstring named `audit_judge.STATE_SYSTEMS` as the trap and then left the surface
    it lands on untested: every test above drives `asked_governance_about`, so an implementation
    could export the borrowed set and keep a private correct one beside it. The export is a
    public name an `experiments/` harness reads; two spellings of the vocabulary that disagree
    is the same defect as two spellings of the predicate."""
    from defender.scripts.governance_reask import GOVERNANCE_SYSTEMS

    assert frozenset(GOVERNANCE) == GOVERNANCE_SYSTEMS, (
        "the exported set is not the design's four — a consumer reading this name and a "
        "consumer calling the function would report different baselines"
    )
    assert not GOVERNANCE_SYSTEMS & frozenset(NOT_GOVERNANCE), (
        "the exported set carries a system that must not count"
    )


def test_a_params_key_is_not_a_params_value_at_any_depth(tmp_path):
    """CLAIM: the key/value distinction holds inside nested containers too.

    `test_a_params_key_is_not_a_params_value` pins it at the top level only, so a walk that
    recurses by flattening `dict.items()` — keys and values alike — passes it and still reads a
    NESTED map keyed by hostname as a question about that host. `params` is model-authored JSON
    of arbitrary depth, and a relationship or tag map keyed by CI name is an ordinary shape for
    one, so this is reachable input rather than a contrived one. A FALSE POSITIVE: it scores an
    ask the run never made."""
    run = _run(
        tmp_path,
        _row("cmdb", {"ci_name": "soc-playground", "filter": {"db-1": "depends_on"}}),
    )
    assert _asked(run, "db-1") is False, (
        "`db-1` is a key one level down — the walk must recurse into values, not into items"
    )
    assert _asked(run, "depends_on") is True, (
        "positive control on the same row: the nested VALUE is a value"
    )
    assert _asked(run, "soc-playground") is True, "positive control: the top-level value"


def test_the_case_fold_holds_at_every_depth(tmp_path):
    """CLAIM: nested leaves fold case exactly as top-level ones do.

    `test_the_name_matches_a_params_value_case_insensitively` uses a FLAT row and every nested
    fixture above is spelled in the same case as the name queried, so an implementation that
    folds at depth 0 and compares nested leaves raw passes both. A FALSE NEGATIVE, and the
    direction that matters most here: it scores a real re-ask as a miss, which reads as "the
    intervention did nothing" on the very comparison O1 is measured by."""
    run = _run(
        tmp_path,
        _row("change-mgmt", {"cis": ["web-2", "DB-1"]}, lead_id="l-002"),
        _row("identity", {"filter": {"scope": {"host": "App-3"}}}, lead_id="l-003"),
    )
    assert _asked(run, "db-1") is True, "a shouted name inside a params list is the same machine"
    assert _asked(run, "app-3") is True, "and so is one inside a nested params object"
    assert _asked(run, "web-3") is False, "negative control: a name neither row carries"


def test_a_params_value_that_is_a_substring_of_the_name_is_not_an_ask(tmp_path):
    """CLAIM: the whole-value rule holds in BOTH directions.

    `test_a_params_value_matches_whole_and_never_by_substring` pins only value ⊃ name (`db-11`,
    `prod-db-1-replica`), leaving `leaf in name` — containment the other way — untouched. A
    governance row carrying a shorter string (a site code, a short CI name, an environment
    token) would then score as an ask about every longer machine name containing it."""
    run = _run(
        tmp_path,
        _row("cmdb", {"host": "db"}, lead_id="l-002"),
        _row("identity", {"scope": "prod"}, lead_id="l-003"),
    )
    assert _asked(run, "db-1") is False, "`db` is a substring of the name and not the subject"
    assert _asked(run, "prod-db-1") is False, "nor is `prod` an ask about `prod-db-1`"
    assert _asked(run, "db") is True, "positive control: the value the first row carried"
    assert _asked(run, "prod") is True, "positive control on the second row"


def test_a_refused_governance_call_counts_as_an_ask(tmp_path):
    """CLAIM: the oracle reads `system` and `params` and NOTHING about the call's outcome — a
    screen-refused, repeat-guarded or above-guard governance row counts.

    THIS PINS THE DESIGN'S LETTER, AND THE DESIGN MAY BE WRONG. M4 says "some row ... has the
    name among its `params` values" and says nothing about outcome. `runtime/query_tool.py`
    writes a row for five calls that never executed, each keeping `system` and `params`
    verbatim: the repeat guard's trip (`∅.repeat-trip`), the three above-guard writers
    (`∅.above-repeat-guard` — the schema rejection, the adapter-load fault, the unresolvable
    verb) and `_screen`'s param/traversal/self-ticket refusal, which keeps an ORDINARY
    `query_id` and stamps `USAGE_EXIT_CODE`. So a run of twelve refused cmdb calls about the
    container scores 12/12. (A POLICY DENIAL is not one of them: `_grant_check`'s `DENIED`
    branch logs to `policy_denials.jsonl` and returns without writing a query row at all.)

    IT IS A DESIGN CALL, NOT A DATA LIMIT — the row carries what would separate the cases, and
    `load_queries` hands both fields over already typed. `QueryRow.is_sentinel` (the writer's
    own `∅.` predicate) covers the four sentinel writers; `exit_code == 0` — `query_tool`'s own
    spelling of "what actually executed" — covers `_screen`'s refusal too. Whether to use them
    turns on what O1 measures: "the run ASKS the governance systems about that machine" reads
    as the act, which a refused call performed, and counting only answered calls would score a
    policy misconfiguration as a failure of the skill-text intervention. Counting refusals,
    though, lets a broken estate manufacture a rate.

    The question is raised on the issue rather than settled here. This test exists so the
    behaviour is VISIBLE and a later flip has to edit a test that explains itself, instead of
    being a silent change to what the experiment's numbers mean — and so that the flip is
    known to be one predicate away rather than blocked on evidence the table does not carry."""
    run = _run(
        tmp_path,
        _row(
            "cmdb",
            {"host": "db-1"},
            query_id="∅.above-repeat-guard",
            exit_code=2,
            payload_status="absent",
            payload_path=None,
        ),
    )
    assert _asked(run, "db-1") is True, (
        "the design's letter counts this row; if that changed, change this test and say so"
    )


def test_a_row_whose_system_cell_is_not_a_string_is_skipped_not_hashed(tmp_path):
    """CLAIM: a `system` cell holding a JSON array or object skips its row and does not raise.

    `system` is a STORED COLUMN read back out of a tree a live box is root on, so its cell is
    not guaranteed to be the string its column declares — and `<cell> in GOVERNANCE_SYSTEMS`
    HASHES the cell, so an unhashable one raises `TypeError` from inside a function whose
    contract is "never raises on a run dir ... one bad tree must not take the batch down".
    Nothing else in this file varies that cell's TYPE: `test_a_malformed_row_is_skipped...`
    covers a row with no `system` at all, and `None` is hashable, so the gap hid behind it.

    The good row is LAST, so an implementation that dies on the bad cell fails rather than
    passing on the row before it."""
    run = _run(
        tmp_path,
        json.dumps({"lead_id": "l-002", "seq": 0, "system": ["cmdb"], "params": {"host": "db-1"}}),
        json.dumps({"lead_id": "l-003", "seq": 1, "system": {"n": "cmdb"}, "params": {"h": "db-1"}}),
        _row("cmdb", {"host": "db-1"}, lead_id="l-004"),
    )
    assert _asked(run, "db-1") is True, (
        "a row whose `system` cell is not a string took the scan down with it — the intact "
        "governance row after it never answered"
    )


def test_a_name_that_is_not_a_string_is_never_an_ask(tmp_path):
    """CLAIM: a non-string subject is False, like the empty one.

    `test_an_empty_name_is_never_an_ask` guards the caller's own `""`, but `None` is the more
    likely spelling of that same harness bug: every name extractor in this tree returns
    `X | None`, so an unresolved subject arrives as `None`, not as `""`. Unguarded,
    `name.strip()` raises `AttributeError` on exactly the population the 0/9 baseline is
    computed over."""
    run = _run(tmp_path, _row("cmdb", {"host": "db-1"}))
    assert _asked(run, None) is False, "a `None` name raised instead of answering False"
    assert _asked(run, 1) is False, "a non-string name raised instead of answering False"
    assert _asked(run, "db-1") is True, "positive control: the fixture does answer True"


def test_a_query_log_that_is_a_directory_answers_false_rather_than_raising(tmp_path):
    """CLAIM: a non-file at the log's path is a False, like an absent one.

    Assumption 6's enumeration stops at "missing", but the same read crosses more faults than
    that. This one is separated from its chmod sibling below deliberately: that test cannot run
    as root, and folding the two together let a skip carry this assertion away with it."""
    as_dir = tmp_path / "log-is-a-dir"
    (as_dir / "executed_queries.jsonl").mkdir(parents=True)
    assert _asked(as_dir, "db-1") is False, "a directory where the log should be must answer False"


def test_an_unreadable_query_log_answers_false_rather_than_raising(tmp_path):
    """CLAIM: an `OSError` reading the log is a False, not an exception.

    A chmod-000 log raises `PermissionError` from the read, which `Path.is_file()` does not
    screen. The repo's neighbouring reader of this exact file already decided the question —
    `record_query.lead_rows` catches `OSError` because "reading this table must never be what
    starts crashing the query tool" — and the oracle scores a BATCH of runs, where one
    unreadable tree must not take the batch down.

    SKIPS AS ROOT — which is NOT how CI runs. `.github/workflows/ci.yml`'s `test` job is a
    bare `runs-on: ubuntu-latest` with no `container:` key, so pytest runs as the unprivileged
    `runner` user and this assertion is gated there. It self-skips in a root devcontainer,
    which is the environment the skip is named for; do not read the skip as "CI never ran
    this" and weaken the catch on that belief."""
    import os

    import pytest

    blocked = _run(tmp_path, _row("cmdb", {"host": "db-1"}), name="blocked")
    log = blocked / "executed_queries.jsonl"
    os.chmod(log, 0o000)
    try:
        if os.access(log, os.R_OK):
            pytest.skip("cannot make a file unreadable as this user (running as root?)")
        assert _asked(blocked, "db-1") is False, "an unreadable log raised instead of answering"
    finally:
        os.chmod(log, 0o644)
    assert _asked(blocked, "db-1") is True, (
        "positive control on the same path: readable again, the answer moves"
    )
