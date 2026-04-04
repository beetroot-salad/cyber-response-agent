# {System} Query Template: {lead-name}

## Entity Field Mapping

| Entity type | Field           | Notes                                  |
|-------------|-----------------|----------------------------------------|
| ip          | {field_name}    | {context}                              |
| user        | {field_name}    | {context, see field-quirks.md}         |
| host        | {field_name}    | {context}                              |

## Base Query

```
{native query in the system's own syntax, with {entity_field} and {entity_value} placeholders}
```

Explain what this query scopes to and any important exclusions.

## Example Invocations

```bash
python3 scripts/siem/{system}_cli.py \
  --query '{base query with concrete values}' \
  --start 2026-01-01T00:00:00Z --window 2h
```

## Customization Notes

- How to narrow/broaden the query for common variations
- Known quirks specific to this query on this system
