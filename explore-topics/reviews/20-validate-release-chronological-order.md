---
name: "Feature Request"
about: Suggest a new feature or enhancement for Vulnlog.
title: "[Feature] Validation rule: warn when releases are not in chronological order"
labels: enhancement
assignees: ''
---

### Feature Description

Add a validation rule that warns when the `releases:` list is not in chronological
order, using the `published_at` dates where present.

### Use Case

The docs require: "Releases must be listed in chronological order (oldest first). This
ordering is used by the CLI to resolve --release filtering." Nothing checks this today,
and the failure mode is silent wrong output, not an error:

With releases listed newest-first (`2.0.0`, `1.0.0`), `vulnlog suppress --release 1.0.0`
includes suppressions for vulnerabilities that only affect `2.0.0`, because "all releases
up to and including 1.0.0" walks the file order. Verified on the current build: a
CVE affecting only `2.0.0` landed in the `.trivyignore.yaml` generated for `--release 1.0.0`.
Reports mis-classify resolutions the same way.

A user who sorts releases newest-first (a natural instinct, changelogs do it) gets wrong
suppression files with exit code 0.

### Proposed Solution (optional)

New rule in `Validator.kt`: for each adjacent pair of releases that both carry
`published_at`, warn when the dates decrease. Severity WARNING (dates are optional, so
the order cannot always be proven). Message should say the filter semantics depend on
the order and point to the docs.

Optionally, the `project-and-releases.adoc` sentence could be linked from the
`--release` flag help, so the assumption is visible where it is used.

### Additional Context (optional)

Found during a code review on the `review` branch (commit f652565).
