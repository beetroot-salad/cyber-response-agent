"""O10/D6: retire the misleading generated roster while preserving its independent audit."""
from __future__ import annotations

import inspect

import pytest

from defender.runtime import verb_roster
from defender.tests._by_path import DEFENDER


def test_committed_roster_and_generation_loading_api_are_retired():
    """O10: a model cannot discover the old roster, and no stale generator can recreate it."""
    assert not (DEFENDER / 'skills' / 'gather' / 'verb-roster.md').exists()
    for name in ('roster_path', 'generate_roster', 'load_roster'):
        assert name not in vars(verb_roster), f'obsolete roster API survives: {name}'


def test_invlang_capability_guidance_names_adapter_declarations_and_no_grant_roster():
    """O10: cap= checks deployment adapter declarations, including withheld capabilities."""
    text = (DEFENDER / 'skills' / 'invlang' / 'SKILL.md').read_text(encoding='utf-8')
    start = text.index('`state=nothing-to-try`')
    end = text.index('`note` is free text', start)
    explanation = text[start:end].lower()
    assert 'cap=' in explanation
    assert 'adapter' in explanation
    assert 'declar' in explanation or 'deploy' in explanation
    assert 'verb-roster.md' not in text
    assert 'same closed roster your `query`' not in explanation


@pytest.mark.parametrize('relative', ['skills/connect/checklist.md',
                                     'scripts/adapters/tacit_knowledge_adapter.py'])
def test_retired_roster_guidance_is_removed(relative):
    """D6: connect no longer cites deleted tests; registry no longer claims audit enumeration."""
    text = (DEFENDER / relative).read_text(encoding='utf-8')
    assert 'test_verb_roster_632.py' not in text
    if relative.endswith('tacit_knowledge_adapter.py'):
        doc = inspect.getdoc(__import__('defender.scripts.adapters.tacit_knowledge_adapter',
                                      fromlist=['registry_path']).registry_path)
        assert 'model_read_surfaces' not in doc


def test_model_surface_enumeration_and_withheld_verb_audit_survive(tmp_path):
    """D6: deleting generator/loader cannot delete the functioning audit of instruction text."""
    tree = tmp_path / 'defender'
    adapters = tree / 'scripts' / 'adapters'
    adapters.mkdir(parents=True)
    (adapters / 'cmdb_adapter.py').write_text(
        "SYSTEM = 'cmdb'\ndef lookup(ctx): pass\nVERBS = {'lookup': lookup}\n", encoding='utf-8')
    skill = tree / 'skills' / 'cmdb' / 'SKILL.md'
    skill.parent.mkdir(parents=True)
    skill.write_text('Use cmdb.lookup to retrieve the host.\n', encoding='utf-8')
    assert skill in verb_roster.model_read_surfaces(tree)
    hits = verb_roster.audit_read_surfaces(tree, {})
    assert len(hits) == 1
    assert 'skills/cmdb/SKILL.md' in hits[0]
    assert 'cmdb.lookup' in hits[0]
    skill.write_text('No query calls are advertised here.\n', encoding='utf-8')
    assert verb_roster.audit_read_surfaces(tree, {}) == (), 'clean control must stay clean'


def test_no_model_facing_instruction_advertises_a_roster_file():
    """O10: removing the one known sentence cannot leave another model-facing file promise."""
    surfaces = {DEFENDER / 'SKILL.md', *verb_roster.model_read_surfaces(DEFENDER),
                DEFENDER / 'skills' / 'connect' / 'checklist.md'}
    offenders = [str(path.relative_to(DEFENDER)) for path in sorted(surfaces)
                 if 'verb-roster.md' in path.read_text(encoding='utf-8')]
    assert offenders == [], f'model instructions still advertise the retired roster: {offenders}'
