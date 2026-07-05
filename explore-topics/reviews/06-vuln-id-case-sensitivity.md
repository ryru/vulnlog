---
name: "Bug Report"
about: Report something that's broken or not working as expected in Vulnlog.
title: "[Bug] Vulnerability IDs are case-sensitive: cve-... and CVE-... become two different entries"
labels: bug
assignees: ''
---

### Describe the Bug

ID prefixes are recognized case-insensitively (`cve-2021-44228` parses fine), but
identity comparison is case-sensitive everywhere. So the same vulnerability written with
different casing is treated as two different vulnerabilities:

- `modify add --vuln-id cve-2021-44228` on a file that already contains
  `CVE-2021-44228` creates a second entry instead of updating the existing one.
- `validate` does not flag the two entries as duplicates, although the schema says the
  ID "must be unique across all entries and aliases".
- The same mismatch affects `modify copy --vuln-id` lookups and alias checks.

Where does the problem occur:

- [x] CLI
- [x] YAML format
- [ ] Suppression output

### Steps to Reproduce

1. Have a file with an entry `id: CVE-2021-44228`.
2. `vulnlog modify add file.vl.yaml --vuln-id cve-2021-44228 --description "x"`
3. Output says "Added" (not "Updated"); the file now has both `CVE-2021-44228` and
   `cve-2021-44228`.
4. `vulnlog validate file.vl.yaml` -> "Validation OK".

### Expected Behavior

IDs that differ only in case are the same ID: `add` updates the existing entry, and
`validate` flags duplicate entries that differ only in case.

### Actual Behavior

A duplicate entry is created and validation stays green.

### Environment (optional)

- **Version:** built from `review` branch, commit f652565

### Additional Context (optional)

There is already a `VulnId.canonical()` helper (uppercase). Suggested fix: normalize the
ID to its canonical form when parsing (`parseVulnId`), so equality, grouping, and lookups
all work on one spelling. Alternatively compare via `canonical()` in the validator, `add`
and `copy` lookups; normalizing at parse time is simpler and keeps one code path.
