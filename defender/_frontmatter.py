from __future__ import annotations

from typing import Any

import yaml

from defender._yaml import compose, safe_load


class FrontmatterError(ValueError):
    pass


#: Frontmatter keys whose entries are KEYS, taken as the text written (#1222 C42): YAML's
#: implicit typing would turn an unquoted `000123`, `yes` or `2026-05-01` into another value, and
#: a signature matches by exact text.
_TEXT_ENTRY_KEYS = ("source_signature",)


def _written_entries(raw: str, key: str) -> list[str] | str | None:
    """`key`'s entries as written (a scalar stays one string), or `None` when the key is not a
    top-level scalar or list of scalars.

    @owns source_signature (the entry text a lesson reader sees)"""
    try:
        root = compose(raw)
    except yaml.YAMLError:
        return None
    if not isinstance(root, yaml.MappingNode):
        return None
    found: yaml.Node | None = None
    for key_node, value_node in root.value:
        if isinstance(key_node, yaml.ScalarNode) and key_node.value == key:
            found = value_node
    if isinstance(found, yaml.ScalarNode):
        return None if found.tag == "tag:yaml.org,2002:null" and not found.value else found.value
    if isinstance(found, yaml.SequenceNode):
        entries: list[str] = []
        for item in found.value:
            if isinstance(item, yaml.ScalarNode):
                entries.append(item.value)
            elif (isinstance(item, yaml.MappingNode) and len(item.value) == 1
                  and isinstance(item.value[0][0], yaml.ScalarNode)
                  and isinstance(item.value[0][1], yaml.ScalarNode)
                  and item.value[0][1].tag == "tag:yaml.org,2002:null"
                  and not item.value[0][1].value):
                # An unquoted `[R-1:]` is the token `R-1:` written; YAML reads it as a mapping.
                entries.append(item.value[0][0].value + ":")
            else:
                return None
        return entries
    return None


def split_frontmatter(text: str) -> tuple[dict[str, Any], str, str]:
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    if not text.startswith("---\n"):
        raise FrontmatterError("missing leading '---' frontmatter fence")
    end = text.find("\n---", 4)
    if end == -1:
        raise FrontmatterError("missing closing '---' frontmatter fence")
    raw = text[4:end]
    try:
        fm = safe_load(raw)
    except yaml.YAMLError as e:
        raise FrontmatterError(f"frontmatter is not valid YAML: {e}") from e
    if not isinstance(fm, dict):
        raise FrontmatterError("frontmatter is not a YAML mapping")
    for key in _TEXT_ENTRY_KEYS:
        if key in fm and (written := _written_entries(raw, key)) is not None:
            fm[key] = written
    nl = text.find("\n", end + 1)
    body = text[nl + 1:].strip() if nl != -1 else ""
    return fm, raw, body


def parse_frontmatter(text: str) -> tuple[dict[str, Any], str]:
    fm, _raw, body = split_frontmatter(text)
    return fm, body


def parse_frontmatter_or_none(text: str) -> dict[str, Any] | None:
    try:
        return parse_frontmatter(text)[0]
    except FrontmatterError:
        return None


def strip_frontmatter(text: str) -> str:
    """The body alone, for splicing a SKILL into a prompt.

    Frontmatter is file metadata, not instructions; in particular a stale `allowed-tools` would
    have the model calling verbs the `ToolSet` never registered. Malformed frontmatter returns
    the text unchanged so a prompt loader never loses a whole SKILL to a YAML slip."""
    try:
        return split_frontmatter(text)[2]
    except FrontmatterError:
        return text
