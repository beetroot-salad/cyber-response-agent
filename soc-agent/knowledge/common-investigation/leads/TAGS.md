# Lead Tags

Each lead's `definition.md` frontmatter carries tags on more than one
dimension — not just "what data source." Today there are two:

- `data_tags: [...]` — abstract data-source tags (e.g. `auth-events`).
  The environment resolves each to a concrete system via
  `environment/data-sources/{tag}.md`. Empty list = meta-lead.
- `baseline: optional | required | not-applicable` — whether the lead's
  output is interpretable without a shift-query comparison.

Expect more tag dimensions to appear over time — don't assume `data_tags`
is the only one when reading or writing a lead.

## Naming convention

Kebab-case (`first-last`, lowercase, hyphen-separated). Applies to tag
*values* (`auth-events`, `not-applicable`) and lead directory names
(`authentication-history`, `source-reputation`).

## Enumerate / search

```bash
# all values in use for a given tag
grep -h '^data_tags:' soc-agent/knowledge/common-investigation/leads/*/definition.md | sort -u
grep -h '^baseline:'  soc-agent/knowledge/common-investigation/leads/*/definition.md | sort -u

# which leads carry a given tag value
grep -l 'auth-events' soc-agent/knowledge/common-investigation/leads/*/definition.md

# all frontmatter keys in use (spot new tag dimensions)
awk '/^---$/{f=!f; next} f && /^[a-z_]+:/' soc-agent/knowledge/common-investigation/leads/*/definition.md | sort -u

# leads missing a given tag (substitute the key)
for f in soc-agent/knowledge/common-investigation/leads/*/definition.md; do
  grep -q '^data_tags:' "$f" || echo "$f"
done
```
