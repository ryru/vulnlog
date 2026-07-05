---
name: "Bug Report"
about: Report something that's broken or not working as expected in Vulnlog.
title: "[Bug] Generic suppression file names use enum casing (github_dependabot.generic.json) instead of canonical reporter names"
labels: bug
assignees: ''
---

### Describe the Bug

Reporters without a native suppression format fall back to the generic JSON format. The
file name is built from the enum constant (`format.reporter.name.lowercase()`), which
yields underscore names like `github_dependabot.generic.json`, `dependency_check.generic.json`,
`npm_audit.generic.json`. Everywhere else (CLI flags, YAML `reporter:` values, docs) the
canonical kebab-case names are used: `github-dependabot`, `dependency-check`, `npm-audit`.

Where does the problem occur:

- [ ] CLI
- [ ] YAML format
- [x] Suppression output

### Steps to Reproduce

1. Create an entry with `reports: [{reporter: github-dependabot, suppress: ...}]`.
2. `vulnlog suppress file.vl.yaml --output-dir out`
3. `ls out`

### Expected Behavior

`github-dependabot.generic.json` (matches the canonical reporter identifier).

### Actual Behavior

`github_dependabot.generic.json`

### Environment (optional)

- **Version:** built from `review` branch, commit f652565

### Additional Context (optional)

One-line fix in `createGenericSuppression` (`SuppressionOutputs.kt`): use the existing
`reporter.canonical()` helper instead of `reporter.name.lowercase()`. Note for anyone
scripting against the current names: this is a small breaking change of the output file
name, best done before more users depend on it. Good first issue.
