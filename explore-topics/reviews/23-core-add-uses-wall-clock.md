---
name: "Feature Request"
about: Suggest a new feature or enhancement for Vulnlog.
title: "[Feature] core Add: inject the current date instead of calling LocalDate.now() inside core"
labels: enhancement
assignees: ''
---

### Feature Description

`mergeReporters` in `modules/lib/src/main/kotlin/dev/vulnlog/lib/core/Add.kt` calls
`LocalDate.now()` to date new reports. Move the date into `AddVulnerabilityOptions`
(for example `reportedAt: LocalDate`) and let the shell (CLI command, Gradle task)
supply it.

### Use Case

The project convention is that core is deterministic and idempotent; the wall clock is
shell input. Concretely:

- Tests for `add` cannot assert the produced YAML byte-for-byte without freezing time.
- Running the same `add` on two machines around midnight produces different files.
- A future `--reported-at` flag (useful when back-filling findings from an older scan)
  falls out for free.

The sibling code already does it right: `SuppressionFilter` takes `today` as a value,
and the CLI passes it in.

### Proposed Solution (optional)

Add a `reportedAt: LocalDate` field to `AddVulnerabilityOptions`, default it at the CLI
boundary (`LocalDate.now()` in `AddCommand`), and use it in `mergeReporters`. No behavior
change for users.

### Additional Context (optional)

Found during a code review on the `review` branch (commit f652565). Small, contained
refactor; a reasonable good-first-issue with a test.
