---
name: "Bug Report"
about: Report something that's broken or not working as expected in Vulnlog.
title: "[Bug] suppress silently drops entries whose ID type does not fit the output format"
labels: bug
assignees: ''
---

### Describe the Bug

Each suppression format accepts only certain ID types (Snyk: `SNYK-*`, cargo-audit:
`RUSTSEC-*`, Trivy: `CVE-*`/`GHSA-*`). Entries whose IDs do not match are filtered out
without any message. The command still prints "Suppression file created at: ..." and
writes a file with zero entries.

The dangerous case: a `not affected` finding reported by Snyk, where the report has no
`vuln_ids` with a `SNYK-*` ID (so the primary CVE is used). The analyst believes the
finding is handled, vulnlog reports success, but `.snyk` contains `ignore: {}` and the
next Snyk scan still fails.

Where does the problem occur:

- [x] CLI
- [ ] YAML format
- [x] Suppression output

### Steps to Reproduce

1. Create an entry `id: CVE-2026-1111` with `reports: [{reporter: snyk, suppress: ...}]`
   and no `vuln_ids`.
2. `vulnlog suppress file.vl.yaml --output-dir out`

### Expected Behavior

A warning on stderr, for example:

```
Warning: CVE-2026-1111 was not written to .snyk: the Snyk format requires SNYK-* IDs.
Add the Snyk ID to reports[snyk].vuln_ids.
```

(Optionally a validation warning for report entries whose reporter has a native format
but no usable ID.)

### Actual Behavior

```
Suppression file created at: .../out/.snyk
```

with content:

```yaml
---
ignore: {}
```

No hint that the entry was dropped.

### Environment (optional)

- **Version:** built from `review` branch, commit f652565

### Additional Context (optional)

The filtering happens in `SuppressionOutputs.kt` (`filter { it.id::class in format.vulnIdTypes }`).
The dropped entries are known at that point, so returning them alongside the output and
letting the CLI/Gradle task print a warning is a contained change. Related detail: the
suppress command also writes empty suppression files for reporters that only appear
outside the current `--release`/`--tag` filter; the same "say what was skipped and why"
approach would cover that.
