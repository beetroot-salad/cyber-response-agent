---
id: host-query.file-stat
status: established
---

## Goal

Current file metadata (permissions, ownership, size, modification time) at a specific path. Answers what the file looks like now on the host.

## What to characterize

- file existence and accessibility status
- file size (bytes)
- modification time
- owner and mode (permissions)

## Query

```
file-stat --path ${file_path}
```

## Common pitfalls

- `file-stat` returns metadata only; it does not read file contents. Use it to confirm presence, size, ownership, mtime; not to inspect the body.
- Symlinks: the command follows symlinks and returns metadata of the target file, not the link itself.
- Answer-key path refusal: the adapter refuses paths under the playground answer-key tree by design; refusal is not missing data.
- Live-host race: file operations may have changed between alert timestamp and query time. Pair with Wazuh historical events for "what was true at time T."
