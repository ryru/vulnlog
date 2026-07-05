---
name: "Bug Report"
about: Report something that's broken or not working as expected in Vulnlog.
title: "[Bug] verdict: under_investigation is accepted by the CLI but invalid per the JSON schema"
labels: bug
assignees: ''
---

### Describe the Bug

The parser accepts `verdict: under_investigation` (mapped to the under-investigation
state), but the published JSON schema only allows `affected`, `not affected`, and
`risk acceptable`; the under-investigation state is expressed by omitting `verdict`.

So a file with `verdict: under_investigation` validates fine in the CLI but is flagged
as invalid by every editor using the `# $schema:` header. The value also breaks the
naming style of the other verdicts (underscore vs. spaces).

A canonical rewrite (`modify copy` on that entry) silently drops the value, because the
domain-to-DTO mapping writes the under-investigation verdict as "field absent".

Where does the problem occur:

- [x] CLI
- [x] YAML format
- [ ] Suppression output

### Steps to Reproduce

1. Set `verdict: under_investigation` on an entry.
2. `vulnlog validate file.vl.yaml` -> "Validation OK".
3. Validate the same file against `schema/vulnlog-v1.json` in an editor -> schema error.

### Expected Behavior

CLI and JSON schema agree on the set of allowed verdict values.

### Actual Behavior

The CLI accepts a value the schema forbids.

### Environment (optional)

- **Version:** built from `review` branch, commit f652565

### Additional Context (optional)

Decision needed: either remove the `"under_investigation"` branch from
`V1Mapper.toDomain` (breaking for files that use it, but the schema never allowed it),
or add the value to the schema. Removing it keeps a single way to express the state
(absence of `verdict`), which matches the documentation.
