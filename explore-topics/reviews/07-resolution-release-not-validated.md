---
name: "Bug Report"
about: Report something that's broken or not working as expected in Vulnlog.
title: "[Bug] resolution.in accepts releases that are not defined in the releases section"
labels: bug
assignees: ''
---

### Describe the Bug

The validator checks that every release in a vulnerability's `releases:` list is defined,
but it never checks `resolution.in`. A typo like `resolution.in: 1.0.1` (when only
`1.0.0` exists) passes validation, and the HTML report then shows a "Fixed in" release
that does not exist.

The schema documentation for `resolution.in` says "Must reference a release ID from the
releases section", so this is a missing rule, not a design decision. Interestingly, the
unreferenced-release INFO rule already counts resolutions as references, so the model
knows about them; only the dangling check is missing.

Where does the problem occur:

- [x] CLI
- [x] YAML format
- [ ] Suppression output

### Steps to Reproduce

1. Create an entry with `resolution: { in: 9.9.9-does-not-exist }` while `releases:`
   only defines `1.0.0`.
2. `vulnlog validate file.vl.yaml`

### Expected Behavior

```
[ERROR] vulnerabilities[CVE-...].resolution: References undefined release '9.9.9-does-not-exist'. ...
```

### Actual Behavior

```
Validation OK
```

### Environment (optional)

- **Version:** built from `review` branch, commit f652565

### Additional Context (optional)

Fix: extend `validateVulnerabilitiesReferenceValidReleases` in
`modules/lib/src/main/kotlin/dev/vulnlog/lib/core/Validator.kt` to also check
`vuln.resolution?.release`, reusing `Rule.DANGLING_RELEASE_REFERENCE`. Good first issue.
