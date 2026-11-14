"""The alert mapping's YAML file format (#1345 O6): a mapping written as a file, parsed to the six entries. No product
command reads such a file since #1470 O1 (`PUT /alert-mapping` is the only writer); it stays apart from
`_alert_input`, whose readers are every run and every process holding the tenant records, so that none of them loads a
YAML parser."""
from __future__ import annotations

import yaml

from defender import _yaml
from defender.records._alert_input import AlertMapping, AlertMappingFault, _reasons, check_mapping


def parse_mapping(text: str) -> AlertMapping:
    """The alert mapping in `text` (YAML: an entry left out or `null` is unmapped), or `AlertMappingFault` carrying a
    fixed reason. A repeated entry is refused: YAML would silently honour the last."""
    repeated = _yaml.duplicate_key_paths(text)
    if repeated:
        raise AlertMappingFault(f"the alert mapping repeats {list(repeated)}: write each entry once")
    try:
        loaded: object = _yaml.safe_load(text)
    except (yaml.YAMLError, RecursionError):
        raise AlertMappingFault(_reasons("yaml")) from None
    mapping: AlertMapping = check_mapping(loaded)
    return mapping
