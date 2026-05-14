You are selecting an investigation seed from a catalog to satisfy a specific evidence need.

# NL goal

{nl_goal}

# Catalog

Each entry: `name` | `tags` | `one-line goal`.

{catalog_manifest}

# Task

Pick the seed(s) that best match the NL goal.

- If one seed satisfies the goal, output: `SELECT <name>`
- If the goal needs evidence from multiple seeds together, output: `SELECT <name1>, <name2>` (comma-separated, in priority order)
- If no catalog seed reasonably matches, output: `PROPOSE_NEW <one-line description of what's needed>`

Output format:
- Optional ≤1 sentence of reasoning.
- Then a single line starting with `SELECT ` or `PROPOSE_NEW `.
- Nothing after that line.
