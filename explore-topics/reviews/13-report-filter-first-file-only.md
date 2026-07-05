---
name: "Bug Report"
about: Report something that's broken or not working as expected in Vulnlog.
title: "[Bug] report: --release and --tag are validated against the first input file only"
labels: bug
assignees: ''
---

### Describe the Bug

`vulnlog report` accepts several input files (one per maintained branch), but the
`--release`/`--tag` filter is resolved once, against the first file only
(`resolveFilter(filterOptions, vulnlogFiles.first())` in `ReportCommand`, same pattern in
`VulnlogReportTask`).

Two effects:

1. A release or tag that exists only in the second file is rejected with
   "Release not found", even though it is valid input.
2. The release set resolved from file 1 ("all releases up to and including X" in file 1
   order) is applied to file 2 as well. Releases of file 2 that are unknown to file 1 are
   silently filtered out, so entries vanish from the report without any message.

Where does the problem occur:

- [x] CLI
- [ ] YAML format
- [ ] Suppression output
- [x] Gradle plugin

### Steps to Reproduce

1. `a.vl.yaml` defines releases `1.0.0`, `1.1.0`; `b.vl.yaml` defines `2.0.0`.
2. `vulnlog report a.vl.yaml b.vl.yaml --release 2.0.0`
   -> "Release not found: 2.0.0", although b.vl.yaml defines it.
3. `vulnlog report a.vl.yaml b.vl.yaml --release 1.1.0`
   -> succeeds, but every entry of b.vl.yaml is silently dropped.

### Expected Behavior

Either resolve the filter per file (each file interprets `--release` against its own
release list, skipping files that do not define it, with a notice), or reject the
combination up front with a clear message that says which file lacks the release.

### Actual Behavior

The first file's release list silently decides for all files.

### Environment (optional)

- **Version:** built from `review` branch, commit f652565

### Additional Context (optional)

The multi-file report is the advertised workflow for maintained branch files, so the
filter semantics deserve a documented decision. Per-file resolution matches the mental
model "one file per branch" best.
