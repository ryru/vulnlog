---
name: "Bug Report"
about: Report something that's broken or not working as expected in Vulnlog.
title: "[Bug] Duplicate release/tag findings print the internal representation, e.g. Release(value=1.0.0)"
labels: bug
assignees: ''
---

### Describe the Bug

The validation messages for duplicate release IDs and duplicate tag IDs interpolate the
domain object instead of its value, so users see Kotlin data-class `toString()` output.

Where does the problem occur:

- [x] CLI
- [ ] YAML format
- [ ] Suppression output

### Steps to Reproduce

1. Define the same release ID twice in `releases:`.
2. `vulnlog validate file.vl.yaml`

### Expected Behavior

```
[ERROR] releases[1.0.0]: Duplicate release ID '1.0.0'.
```

### Actual Behavior

```
[ERROR] releases[1.0.0]: Duplicate release ID 'Release(value=1.0.0)'.
```

Tags produce the same pattern: `Duplicate tag ID 'Tag(value=...)'.`

### Environment (optional)

- **Version:** built from `review` branch, commit f652565

### Additional Context (optional)

In `Validator.kt`, `validateUniqueReleases` and `validateUniqueTags` use `'$id'` where
the sibling rule `validateUniqueVulnerabilities` correctly uses `id.canonical()`. Use
`id.value` in both messages and extend the existing validator tests to assert the
message text. Good first issue.
