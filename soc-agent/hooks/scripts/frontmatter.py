"""YAML frontmatter parser.

Parses the YAML frontmatter block (between ``---`` delimiters) at the
start of a Markdown file using PyYAML.
"""

import yaml


def parse_yaml_frontmatter(text: str) -> dict:
    """Parse YAML frontmatter from a Markdown file.

    Expects content between ``---`` delimiters at the start of the file.
    Returns an empty dict if no frontmatter is found or if parsing fails.
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

    if not fm_lines:
        return {}

    block = "\n".join(fm_lines)
    try:
        result = yaml.safe_load(block)
    except yaml.YAMLError:
        return {}
    if not isinstance(result, dict):
        return {}
    return result
