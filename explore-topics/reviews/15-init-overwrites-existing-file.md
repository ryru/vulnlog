---
name: "Bug Report"
about: Report something that's broken or not working as expected in Vulnlog.
title: "[Bug] init overwrites an existing file without asking"
labels: bug
assignees: ''
---

### Describe the Bug

`vulnlog init -o vulnlog.yaml` writes the scaffold unconditionally. If the path already
contains a curated Vulnlog file (months of triage analysis), it is replaced by the empty
scaffold with no warning. The Gradle `vulnlogInit` task behaves the same.

The whole point of Vulnlog is that this one file is the single source of truth, so this
is the most valuable file in the repository to protect. It is usually under version
control, but not always (first import, generated workspaces).

Where does the problem occur:

- [x] CLI
- [ ] YAML format
- [ ] Suppression output
- [x] Gradle plugin

### Steps to Reproduce

1. Have an existing, non-empty `vulnlog.yaml`.
2. `vulnlog init --organization X --name Y --author Z -o vulnlog.yaml`

### Expected Behavior

```
Error: vulnlog.yaml already exists. Use --force to overwrite.
```

Exit code 1, file untouched.

### Actual Behavior

```
Vulnlog file created at: /path/to/vulnlog.yaml
```

The previous content is gone.

### Environment (optional)

- **Version:** built from `review` branch, commit f652565

### Additional Context (optional)

Small change in `writeInit` (CLI) and `VulnlogInitTask` (Gradle): refuse when the target
exists, plus a `--force` flag. Good first issue.
