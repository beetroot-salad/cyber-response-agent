"""O4 — a profile cannot silence the alert it degrades (guard mechanism M3).

The guard reads the real `detection-rules/*.json` at activate time and builds
two sets:

  * rule-key fields — from the `threshold.field` JSON array *and* from the
    parsed query/EQL string. Reading only the query string is the design's own
    stated near-miss: `source.ip` is keyed on by v2-bulk-ssh-success and appears
    **nowhere** in any rule's query text.
  * rule-read datasets — the dataset behind each rule's `index` pattern.

Both sides speak the stack's vocabulary — a dataset names exactly one
pipeline, a mutation carries every field its processor touches — so every
check is exact set membership. There is no glob to translate at check time,
which is where the previous bypasses lived (a wider stream glob, a bare
dataset name, a rename's untouched `to` field). Every case below is grounded
in the committed rules, not in invented field names.
"""
from __future__ import annotations

import json

import pytest
from _fakes import FakeExecSeam, write_profile

from chaos.guard import GuardRefused, check_mutations, check_profile, rule_key_fields, rule_read_datasets
from chaos.mutations import UnresolvableProfile, resolve_mutations
from chaos.profiles import load_profile

# Keyed on only via `threshold.field` — a query-string-only parser misses these.
THRESHOLD_ONLY_FIELDS = ["source.ip", "falco.output_fields.container.name"]
# Keyed on only via the query/EQL text.
QUERY_ONLY_FIELDS = ["process.name", "event.outcome", "falco.rule"]
# Investigation-read fields no rule keys on — the legal schema-drift targets.
SAFE_DRIFT_FIELDS = ["user.name", "source.port", "system.auth.ssh.method"]


def test_threshold_only_fields_really_are_absent_from_every_query(rules_dir):
    """Grounds the near-miss: prove the premise from the committed rules."""
    queries = " ".join(
        json.loads(p.read_text()).get("query", "") for p in sorted(rules_dir.glob("*.json"))
    )
    for field in THRESHOLD_ONLY_FIELDS:
        assert field not in queries, f"{field} is in a query string — premise stale"


def test_rule_key_fields_covers_threshold_array_and_query_text(rules_dir):
    fields = rule_key_fields(rules_dir)
    for field in THRESHOLD_ONLY_FIELDS + QUERY_ONLY_FIELDS + ["host.name"]:
        assert field in fields, f"{field} missing from rule-key fields"
    for field in SAFE_DRIFT_FIELDS:
        assert field not in fields, f"{field} wrongly treated as a rule-key field"


def test_rule_read_datasets_is_every_rule_index_dataset(rules_dir):
    assert rule_read_datasets(rules_dir) == {"system.auth", "falco.alerts"}


# -- schema-drift: fields ------------------------------------------------------------


@pytest.mark.parametrize("field", THRESHOLD_ONLY_FIELDS + QUERY_ONLY_FIELDS)
def test_schema_drift_on_a_rule_key_field_is_refused(profiles_dir, rules_dir, field):
    write_profile(
        profiles_dir,
        "drift-bad",
        "schema-drift",
        {"rename": {"from": field, "to": f"{field}.renamed"}},
    )
    profile = load_profile("drift-bad", profiles_dir=profiles_dir)
    with pytest.raises(GuardRefused):
        check_profile(profile, rules_dir=rules_dir)


@pytest.mark.parametrize("field", SAFE_DRIFT_FIELDS)
def test_schema_drift_on_a_non_rule_field_is_accepted(profiles_dir, rules_dir, field):
    write_profile(
        profiles_dir,
        "drift-ok",
        "schema-drift",
        {"rename": {"from": field, "to": f"{field}_legacy"}},
    )
    profile = load_profile("drift-ok", profiles_dir=profiles_dir)
    check_profile(profile, rules_dir=rules_dir)  # must not raise


def test_schema_drift_remove_variant_is_guarded_too(profiles_dir, rules_dir):
    write_profile(profiles_dir, "drift-remove-bad", "schema-drift", {"remove": "event.outcome"})
    with pytest.raises(GuardRefused):
        check_profile(load_profile("drift-remove-bad", profiles_dir=profiles_dir), rules_dir=rules_dir)

    write_profile(profiles_dir, "drift-remove-ok", "schema-drift", {"remove": "source.port"})
    check_profile(load_profile("drift-remove-ok", profiles_dir=profiles_dir), rules_dir=rules_dir)


@pytest.mark.parametrize(
    "params",
    [
        {"remove": "event"},  # takes event.outcome with it: both EQL sequence rules + both sshd thresholds
        {"rename": {"from": "process", "to": "proc"}},  # takes process.name
        {"remove": "source"},  # takes source.ip (v2-bulk-ssh-success, threshold-only)
        {"rename": {"from": "falco", "to": "falco_legacy"}},  # takes falco.rule
    ],
)
def test_schema_drift_on_an_ancestor_of_a_rule_key_field_is_refused(profiles_dir, rules_dir, params):
    """A rename/remove of an object field takes every field nested under it.
    An exact-string compare of the profile's target against the rules' field
    names accepted all of these — none of them is literally a rule-key field,
    every one of them silences a rule."""
    write_profile(profiles_dir, "drift-ancestor", "schema-drift", params)
    with pytest.raises(GuardRefused):
        check_profile(load_profile("drift-ancestor", profiles_dir=profiles_dir), rules_dir=rules_dir)


def test_schema_drift_on_a_sibling_with_a_shared_prefix_is_not_refused(profiles_dir, rules_dir):
    """`source.port` is not under `source.ip` (and `sourcefile` would not be
    under `source`): the ancestor test is on dotted path segments, not on
    string prefixes."""
    write_profile(profiles_dir, "drift-sibling", "schema-drift", {"remove": "source.port"})
    check_profile(load_profile("drift-sibling", profiles_dir=profiles_dir), rules_dir=rules_dir)


@pytest.mark.parametrize("to", ["event.outcome", "source.ip", "event", "process"])
def test_schema_drift_renaming_onto_a_rule_key_field_is_refused(profiles_dir, rules_dir, to):
    """A rename touches two fields. Renaming an innocent field *onto* a
    rule-key field (or an ancestor of one) writes foreign values into what
    the rule keys on — polluting evidence rather than silencing it, which
    is still the rule being degraded."""
    write_profile(profiles_dir, "drift-onto", "schema-drift", {"rename": {"from": "user.name", "to": to}})
    with pytest.raises(GuardRefused):
        check_profile(load_profile("drift-onto", profiles_dir=profiles_dir), rules_dir=rules_dir)


# -- data-drop: datasets --------------------------------------------------------------


@pytest.mark.parametrize("dataset", ["system.auth", "falco.alerts"])
def test_data_drop_on_a_rule_read_dataset_is_refused(profiles_dir, rules_dir, dataset):
    """Any drop on a rule-read dataset breaks the two EQL sequence rules at
    any nonzero rate — the reason selective auth drops were deferred."""
    write_profile(profiles_dir, "drop-bad", "data-drop", {"dataset": dataset, "rate": 25})
    with pytest.raises(GuardRefused):
        check_profile(load_profile("drop-bad", profiles_dir=profiles_dir), rules_dir=rules_dir)


def test_data_drop_on_the_day_one_safe_dataset_is_accepted(profiles_dir, rules_dir):
    write_profile(profiles_dir, "drop-ok", "data-drop", {"dataset": "system.syslog", "rate": 25})
    check_profile(load_profile("drop-ok", profiles_dir=profiles_dir), rules_dir=rules_dir)


@pytest.mark.parametrize(
    "dataset",
    ["logs-*", "logs-system.*", "*", "system.*", "logs-system.auth-*", "logs-system.auth", "system.auth-default", ""],
)
def test_a_data_drop_target_that_is_not_a_dataset_is_refused_as_malformed(profiles_dir, dataset, inventory):
    """Every previous bypass was a spelling: a wider glob, a bare stream
    name, a parent pipeline. None of these names exactly one ingest
    pipeline, so none is a valid target — refused before the guard, with
    nothing to translate."""
    write_profile(profiles_dir, "drop-spelling", "data-drop", {"dataset": dataset, "rate": 25})
    profile = load_profile("drop-spelling", profiles_dir=profiles_dir)
    with pytest.raises(UnresolvableProfile):
        resolve_mutations(profile, seed=42, inventory=inventory)


def test_a_rule_reading_a_wide_index_pattern_refuses_every_data_drop(tmp_path, profiles_dir):
    """A rule over `logs-*` reads every dataset; while it exists no drop is
    safe, whatever dataset the profile names."""
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "wide.json").write_text(json.dumps({"rule_id": "wide", "query": "", "index": ["logs-*"]}))
    write_profile(profiles_dir, "drop-any", "data-drop", {"dataset": "system.syslog", "rate": 5})
    with pytest.raises(GuardRefused):
        check_profile(load_profile("drop-any", profiles_dir=profiles_dir), rules_dir=rules_dir)


def test_check_mutations_gates_on_what_was_actually_resolved(rules_dir):
    """The push is gated on the resolved mutations, not on the profile text:
    a mutation whose processor touches a rule-key ancestor, or whose
    dataset a rule reads, is refused even if some future resolver produced
    it from an innocent-looking profile."""
    with pytest.raises(GuardRefused):
        check_mutations(
            [
                {
                    "kind": "schema-drift",
                    "dataset": "system.auth",
                    "pipeline": "logs-system.auth@custom",
                    "processor": {"remove": {"field": "event", "ignore_missing": True, "ignore_failure": True}},
                    "fields": ["event"],
                }
            ],
            rules_dir=rules_dir,
        )
    with pytest.raises(GuardRefused):
        check_mutations(
            [{"kind": "data-drop", "dataset": "system.auth", "pipeline": "logs-system.auth@custom",
              "processor": {}, "fields": []}],
            rules_dir=rules_dir,
        )
    check_mutations(
        [
            {
                "kind": "data-drop",
                "dataset": "system.syslog",
                "pipeline": "logs-system.syslog@custom",
                "processor": {"drop": {"if": "true"}},
                "fields": [],
            }
        ],
        rules_dir=rules_dir,
    )


def test_rule_key_fields_and_datasets_are_empty_for_an_empty_rules_dir(tmp_path):
    """The guard must actually read `rules_dir`, not answer from a fixed
    table hand-transcribed from today's committed rules — a hardcoded set
    would return the same fields regardless of what's on disk."""
    empty = tmp_path / "no-rules"
    empty.mkdir()
    assert rule_key_fields(empty) == set()
    assert rule_read_datasets(empty) == set()


def test_guard_reacts_to_a_rule_not_in_the_committed_set(tmp_path, profiles_dir):
    """A synthetic rule the committed detection-rules/ doesn't have, keying on
    a field this suite otherwise treats as safe (user.name) over a dataset
    this suite otherwise treats as safe (system.syslog). If the guard
    answers from the real committed rules alone rather than `rules_dir`, both
    profiles below wrongly activate."""
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "new-rule.json").write_text(
        json.dumps(
            {
                "rule_id": "new-rule",
                "query": "",
                "threshold": {"field": ["user.name"]},
                "index": ["logs-system.syslog-*"],
            }
        )
    )

    write_profile(
        profiles_dir, "drift-newly-bad", "schema-drift", {"rename": {"from": "user.name", "to": "user.id"}}
    )
    with pytest.raises(GuardRefused):
        check_profile(load_profile("drift-newly-bad", profiles_dir=profiles_dir), rules_dir=rules_dir)

    write_profile(profiles_dir, "drop-newly-bad", "data-drop", {"dataset": "system.syslog", "rate": 10})
    with pytest.raises(GuardRefused):
        check_profile(load_profile("drop-newly-bad", profiles_dir=profiles_dir), rules_dir=rules_dir)


def test_activate_runs_the_guard_before_touching_the_stack(profiles_dir, rules_dir, ledger_dir):
    """A refused profile must mutate nothing — the guard is a precondition of
    activate, not a report written after the fact."""
    from chaos import ctl

    write_profile(
        profiles_dir,
        "drift-source-ip",
        "schema-drift",
        {"rename": {"from": "source.ip", "to": "source.address"}},
    )
    execer = FakeExecSeam()
    with pytest.raises(GuardRefused):
        ctl.activate(
            "drift-source-ip",
            execer=execer,
            profiles_dir=profiles_dir,
            rules_dir=rules_dir,
            ledger_dir=ledger_dir,
        )
    assert execer.mutating_calls() == []
    assert list(ledger_dir.iterdir()) == []
