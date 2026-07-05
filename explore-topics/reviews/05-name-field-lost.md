---
name: "Bug Report"
about: Report something that's broken or not working as expected in Vulnlog.
title: "[Bug] Vulnerability name is never shown in reports and is deleted by modify copy"
labels: bug
assignees: ''
---

### Describe the Bug

The `name` field of a vulnerability entry (for example `name: Log4Shell`) is parsed from
YAML into the DTO but never mapped into the domain model: `V1Mapper.vulnerabilitiesToDomain`
does not pass `name` to `VulnerabilityEntry`. Two user-visible consequences:

1. The HTML report never shows the common name, although the model documentation says
   "Displayed prominently in reports".
2. `modify copy` silently deletes `name` from copied entries, because copy goes through
   the domain model and writes the entry back without it. The cli-copy docs explicitly
   list `name` as a merged scalar field, which cannot work today.

Where does the problem occur:

- [x] CLI
- [x] YAML format
- [ ] Suppression output

### Steps to Reproduce

1. Create an entry with `name: Log4Shell`.
2. `vulnlog report file.vl.yaml -o report.html` and search the report for "Log4Shell":
   zero matches.
3. `vulnlog modify copy file.vl.yaml target.vl.yaml --vuln-id CVE-2021-44228`:
   the entry in `target.vl.yaml` has no `name` field.

### Expected Behavior

`name` survives parsing, shows up in the HTML report next to the primary ID, and is
carried over (and merged) by `modify copy`.

### Actual Behavior

`name` is dropped at the DTO-to-domain boundary. Reports never contain it and copy
erases it in target files.

### Environment (optional)

- **Version:** built from `review` branch, commit f652565

### Additional Context (optional)

Fix in three small steps:

1. Map `name = vulnerability.name` in `V1Mapper.vulnerabilitiesToDomain`.
2. Add `name` to `ReportingEntry` and to the report JSON in `HtmlReportMapper`
   (and render it in the template).
3. Add a round-trip test: YAML with `name` -> domain -> DTO keeps the value.
