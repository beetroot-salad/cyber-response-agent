---
id: host-query.package-installed
status: established
---

## Goal

Current debian package installation state and version. Answers whether a package is installed and at what version on a single host.

## What to summarize

- package installation status (installed or not installed)
- installed version if present

## Query

```
package-installed --name ${package_name}
```

## Common pitfalls

- Package names differ between dpkg and apt. Use the debian package name as it appears in dpkg, not the source-tarball name.
- Version queries are point-in-time; if the host is mid-upgrade, the state may be transitional.
