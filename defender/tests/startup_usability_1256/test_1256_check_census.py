"""#1256 O-5, the key census: for each adapter, a settings check that raises `ConfigFault`
exactly where its own verbs do.

O-5: "for each adapter, every `ConfigFault` any verb can raise is also raised by its check
(observable per adapter: settings that make a verb raise make the check raise)". K1: the check
returns None when the system is usable. Both directions are judged here, case by case, with the
adapter's OWN verbs as the oracle — never a list of expected outcomes written by hand:

  * the mutations are GENERATED from the settings a complete planted tenant carries
    (`_spec1107.config_texts`): every key of each system's `config.env` absent, blank and
    whitespace-only, and — for a key whose name says it carries a timeout or an access method —
    every way of breaking the grammar a loader judges (`_GRAMMAR`). A check that asks only what a
    hand-written table names (#1042: a member named in prose and missing from the tuple) meets
    every key and every grammar here;
  * each case resolves the mutated tenant with the real resolver and calls EVERY verb of the
    adapter over the record (`_every_verb`, the docker CLI shimmed). If some verb raises
    `ConfigFault`, the check must raise `ConfigFault` naming the key. If none does and the
    health-check answers, the system is usable and the check must return None — a key no verb
    needs (elastic's Kibana container, its TLS flag) must not take the system down at start.

As in `test_1256_adapter_checks.py`, the disk is put back complete before the verbs and the check
are asked: both read the RECORD (K1, DP1), never the file.

The file families (no folder, a stored fault) stay in `test_1256_adapter_checks.FAULTS`; the
system list is that table's, so a roster adapter with no row there fails its census test.
"""
from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from defender.runtime.tenant_settings import SystemConfig
from defender.scripts.adapters.faults import ConfigFault
from defender.tests.startup_usability_1256.test_1256_adapter_checks import (
    FAULTS,
    Family,
    _adapter,
    _check_outcome,
    _ctx,
    _declared_check,
    _every_verb,
    _plant,
)
from defender.tests.tenant_1107_settings import _spec1107 as S

MARKER = "o5k"

#: Values every key is tried with: blank and whitespace-only (`tenant_settings.is_blank`).
_EVERY_KEY: tuple[tuple[str, str], ...] = (("blank", ""), ("whitespace", "   "))

#: The value grammars a loader judges beyond presence, by the key name's suffix (grounded at
#: d7b1886d: `_stub_transport.load_config`'s timeout rule, `access_context`'s one implemented
#: access method). Each value breaks the grammar in a different way; a check that tests only one
#: of them (`!= "0"`, `int(...) > 0`, `isdigit()`) passes another.
_GRAMMAR: dict[str, tuple[tuple[str, str], ...]] = {
    "_TIMEOUT_SEC": (("non-numeric", "abc"), ("negative", "-5"), ("fractional", "1.5"),
                     ("zero", "0"), ("ten-digits", "1234567890"), ("padded", " 10"),
                     ("non-ascii-digits", "١٠")),
    "_TRANSPORT": (("other-method", "http"), ("other-case", "Docker-Exec")),
}


def _keys(text: str) -> list[str]:
    """The keys a planted `config.env` text sets, in file order."""
    return [line.split("=", 1)[0].strip() for line in text.splitlines()
            if "=" in line and not line.lstrip().startswith("#")]


def _dropping(key: str) -> Callable[[Path, str], Any]:
    return lambda folder, system: S.drop_key(folder, system, key)


def _setting(key: str, value: str) -> Callable[[Path, str], Any]:
    return lambda folder, system: S.set_key(folder, system, key, value)


def _mutations(key: str) -> list[Family]:
    families = [Family(f"{key}-absent", "drop", (key,), _dropping(key), key=key)]
    grammar = [g for suffix, values in _GRAMMAR.items() if key.endswith(suffix) for g in values]
    for label, value in (*_EVERY_KEY, *grammar):
        families.append(Family(f"{key}-{label}", "set", (key,), _setting(key, value),
                               key=key, value=value))
    return families


def _key_cases() -> list[Any]:
    texts = S.config_texts(MARKER)
    return [pytest.param(system, family, id=f"{system}-{family.label}")
            for system in sorted(FAULTS) if FAULTS[system]
            for key in _keys(texts.get(system, ""))
            for family in _mutations(key)]


def _landed(record: Any, system: str, family: Family) -> bool:
    entry = record.systems.get(system)
    if not isinstance(entry, SystemConfig):
        return False
    if family.kind == "drop":
        return family.key not in entry
    return entry.get(family.key) == family.value


def test_o5_the_key_census_covers_every_settings_reading_adapter() -> None:
    """The generator's own premise: every adapter whose settings are judged (a FAULTS row with
    file families) has a planted `config.env` with keys to mutate, and the grammars each reach at
    least one planted key — so no adapter, and no grammar, leaves the census empty."""
    texts = S.config_texts(MARKER)
    readers = sorted(s for s, families in FAULTS.items() if families)
    assert readers, "precondition: FAULTS names settings-reading adapters"
    empty = [s for s in readers if not _keys(texts.get(s, ""))]
    assert empty == [], f"settings-reading adapters with no planted key to mutate: {empty}"
    every_key = [k for s in readers for k in _keys(texts[s])]
    unused = [suffix for suffix in _GRAMMAR if not any(k.endswith(suffix) for k in every_key)]
    assert unused == [], f"grammars no planted key carries (the census skips them): {unused}"


@pytest.mark.parametrize(("system", "family"), _key_cases())
def test_o5_the_check_raises_exactly_where_a_verb_raises(
        tmp_path, checkout_roster, system, family):
    """O-5 / K1, one generated mutation of one key of `system`'s complete settings. The verbs are
    the oracle: if any verb raises ConfigFault over the mutated record, the check raises
    ConfigFault naming the key; if none does and the health-check answers, the check returns
    None."""
    module = _adapter(checkout_roster, system)
    root, folder = _plant(tmp_path, MARKER)
    family.mutate(folder, system)
    record = S.resolve(root)
    assert _landed(record, system, family), (
        f"precondition: the {family.label} mutation reached the record: "
        f"{record.systems.get(system)!r}")
    # The disk is complete again; the record is not (K1, DP1: the check reads the record).
    S.write_config(folder, system, S.config_texts(MARKER)[system])

    shim = S.DockerShim(tmp_path / "shim")
    outcomes = _every_verb(module, _ctx(record, tmp_path, shim))
    raising = {v: str(e) for v, e in outcomes.items() if isinstance(e, ConfigFault)}
    if raising:
        assert any(family.key in text for text in raising.values()), (
            f"premise: the verbs' fault names {family.key}: {raising}")
        fault = _check_outcome(_declared_check(module, system), record)
        assert isinstance(fault, ConfigFault), (
            f"O-5: {system}'s verbs {sorted(raising)} raise ConfigFault under {family.label}, so "
            f"its settings check must raise ConfigFault over the same record — got {fault!r}")
        assert family.key in str(fault), (
            f"K1: {system}'s check must name what is wrong ({family.key}): {fault}")
        return

    assert "health-check" in outcomes, f"premise: {system} declares health-check: {sorted(outcomes)}"
    assert outcomes["health-check"] is None, (
        f"premise: under {family.label} no {system} verb raises ConfigFault and its health-check "
        f"answers — got {outcomes['health-check']!r}")
    fault = _check_outcome(_declared_check(module, system), record)
    assert fault is None, (
        f"K1: under {family.label} every {system} verb answers without a ConfigFault, so the "
        f"system is usable and its check must not raise (it would be down at start for a "
        f"setting no verb needs) — got {fault!r}")
