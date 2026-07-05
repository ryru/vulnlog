---
name: "Bug Report"
about: Report something that's broken or not working as expected in Vulnlog.
title: "[Bug] Gradle vulnlogSuppress can keep expired suppressions: the current date is not a task input"
labels: bug
assignees: ''
---

### Describe the Bug

Suppression generation filters out entries whose `expires_at` has passed, so the output
depends on the current date. The `VulnlogSuppressTask` is `@CacheableTask` and declares
only files, filter options, and format as inputs; the date is not an input.

Consequences in a normal Gradle setup:

- Up-to-date check: the task ran yesterday, nothing changed in the inputs, a suppression
  expires today. The next build says `UP-TO-DATE` and the expired suppression stays in
  the generated file.
- Build cache: a cache hit restores output computed on an earlier date, with the same
  effect.

This quietly undermines "suppressions expire automatically" for Gradle users; the CLI is
not affected.

Where does the problem occur:

- [ ] CLI
- [ ] YAML format
- [x] Suppression output
- [x] Gradle plugin

### Steps to Reproduce

1. Configure `vulnlogSuppress` with a suppression whose `expires_at` is tomorrow.
2. Run the task today; the entry is in the output (correct).
3. Run the task again after the expiry date without changing any input file.
4. Task is `UP-TO-DATE`; the output still contains the expired suppression.

### Expected Behavior

Suppression files regenerated on or after the expiry date no longer contain the entry,
also in incremental or cached builds.

### Actual Behavior

The stale output is kept until some other input changes.

### Additional Context (optional)

Options, roughly in order of preference:

1. Add the evaluation date as an `@Input` (for example
   `today.convention(providers.provider { LocalDate.now().toString() })`). Cache and
   up-to-date then naturally invalidate once per day. Also makes the date user-settable,
   which helps reproducible builds.
2. Or mark the task non-cacheable and always-out-of-date when any entry carries an
   expiry date.

- **Version:** built from `review` branch, commit f652565
