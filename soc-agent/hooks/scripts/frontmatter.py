"""YAML frontmatter parser — zero external dependencies.

Parses the YAML frontmatter block (between ``---`` delimiters) at the
start of a Markdown file. Covers the subset of YAML used in this project:

- Scalar values: strings, integers, ``null``/``~``, quoted strings
- Inline lists: ``[a, b, c]``
- Block lists of scalars: indented ``- item`` lines
- Block lists of dicts: indented ``- key: value`` lines, with subsequent
  more-indented ``key: value`` lines added to the same dict
- One level of nesting: indented ``key: value`` under a parent key

This is intentionally NOT a full YAML parser. It exists so that hooks
(safety-critical, must run everywhere) have zero external dependencies.
If you need richer YAML support, use ``yaml.safe_load`` from PyYAML in
non-hook code where dependencies are acceptable.

Limitations:
- Only one level of nesting (no dicts within dicts within lists, etc.)
- No multi-line string values (``|``, ``>``)
- No anchors/aliases (``&``, ``*``)
- No flow mappings (``{key: value}``)
- Inline list items cannot contain commas
- No type coercion beyond int and null (no floats, bools, dates)
"""


def _parse_scalar(value: str):
    """Parse a single YAML scalar value.

    Handles: null/~/empty → None, digit strings → int,
    quoted strings → unquoted, everything else → str.
    """
    if value.lower() in ("null", "~", ""):
        return None
    if value.isdigit():
        return int(value)
    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        return value[1:-1]
    if len(value) >= 2 and value[0] == "'" and value[-1] == "'":
        return value[1:-1]
    return value


def _parse_inline_list(value: str) -> list:
    """Parse an inline YAML list like ``[a, b, c]``.

    Returns an empty list for ``[]``.
    """
    inner = value[1:-1].strip()
    if not inner:
        return []
    return [_parse_scalar(item.strip()) for item in inner.split(",")]


def parse_yaml_frontmatter(text: str) -> dict:
    """Parse YAML frontmatter from a Markdown file.

    Expects content between ``---`` delimiters at the start of the file.
    Returns an empty dict if no frontmatter is found.
    """
    lines = text.strip().split("\n")
    if not lines or lines[0].strip() != "---":
        return {}

    # Extract lines between the opening and closing --- delimiters.
    fm_lines = []
    for line in lines[1:]:
        if line.strip() == "---":
            break
        fm_lines.append(line)

    fields: dict = {}
    current_key: str | None = None  # Tracks parent key for indented content
    current_list_item: dict | None = None  # Tracks latest dict in a list-of-dicts

    for line in fm_lines:
        indent = len(line) - len(line.lstrip())
        stripped = line.strip()

        if not stripped:
            continue

        # Indented line — belongs to current_key (list item or nested key).
        if indent > 0 and current_key is not None:
            if stripped.startswith("- "):
                item_content = stripped[2:].strip()
                if not isinstance(fields[current_key], list):
                    fields[current_key] = []
                # "- key: value" starts a new dict in the list; "- scalar"
                # appends a plain scalar.
                if ":" in item_content:
                    sub_key, _, sub_value = item_content.partition(":")
                    new_item = {sub_key.strip(): _parse_scalar(sub_value.strip())}
                    fields[current_key].append(new_item)
                    current_list_item = new_item
                else:
                    fields[current_key].append(_parse_scalar(item_content))
                    current_list_item = None
            elif ":" in stripped:
                sub_key, _, sub_value = stripped.partition(":")
                if current_list_item is not None:
                    # Belongs to the latest dict appended to the list.
                    current_list_item[sub_key.strip()] = _parse_scalar(
                        sub_value.strip()
                    )
                else:
                    if not isinstance(fields[current_key], dict):
                        fields[current_key] = {}
                    fields[current_key][sub_key.strip()] = _parse_scalar(
                        sub_value.strip()
                    )
            continue

        # Top-level key: value line — reset list-item context.
        current_list_item = None
        if ":" in stripped:
            key, _, value = stripped.partition(":")
            key = key.strip()
            value = value.strip()

            if value.startswith("[") and value.endswith("]"):
                fields[key] = _parse_inline_list(value)
            elif value.lower() in ("null", "~", ""):
                fields[key] = None
            else:
                fields[key] = _parse_scalar(value)

            current_key = key

    return fields
