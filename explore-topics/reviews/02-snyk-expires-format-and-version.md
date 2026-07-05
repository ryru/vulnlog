---
name: "Bug Report"
about: Report something that's broken or not working as expected in Vulnlog.
title: "[Bug] Generated .snyk ignores never expire: expires needs an ISO datetime, version field is missing"
labels: bug
assignees: ''
---

### Describe the Bug

The generated `.snyk` policy file writes `expires: 2026-08-01` (date only). Snyk requires
the JavaScript date-time string format `YYYY-MM-DDThh:mm:ss.fffZ`. The Snyk docs state:
"If the specified expiration date does not adhere to this format, the ignore will be
respected and persist indefinitely." So temporary Snyk suppressions never expire.

The file is also missing the top-level `version` field (for example `version: v1.25.0`)
that every documented `.snyk` file carries.

Where does the problem occur:

- [ ] CLI
- [ ] YAML format
- [x] Suppression output

### Steps to Reproduce

1. Create a Vulnlog file with a Snyk report, a `vuln_ids: [SNYK-JS-EXAMPLE-1234567]` entry,
   and `suppress.expires_at: 2026-08-01`.
2. Run `vulnlog suppress vulnlog.yaml --output-dir out`.
3. Look at `out/.snyk`.

### Expected Behavior

```yaml
version: v1.25.0
ignore:
  SNYK-JS-EXAMPLE-1234567:
  - '*':
      reason: temp suppression
      expires: 2026-08-01T00:00:00.000Z
```

### Actual Behavior

```yaml
---
ignore:
  SNYK-JS-EXAMPLE-1234567:
  - '*':
      reason: temp suppression
      expires: 2026-08-01
```

Per Snyk's documented behavior, the malformed `expires` makes the ignore permanent.

### Environment (optional)

- **Version:** built from `review` branch, commit f652565

### Additional Context (optional)

References:

- https://docs.snyk.io/manage-risk/policies/the-.snyk-file
- https://docs.snyk.io/developer-tools/snyk-cli/commands/ignore

Fix: serialize `expires` as `<date>T00:00:00.000Z` in `SnykIgnoreEntryDto` and add a
`version` field to `SnykSuppressionDto`. Same remark as for the Trivy output: a golden
test on the rendered file content would catch format regressions.
