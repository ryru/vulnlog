---
name: "Feature Request"
about: Suggest a new feature or enhancement for Vulnlog.
title: "[Feature] Parse errors should name the entry and report all problems at once"
labels: enhancement
assignees: ''
---

### Feature Description

Make DTO-to-domain parse errors actionable: include the vulnerability ID (or YAML path)
of the offending entry, and collect all errors in one pass instead of stopping at the
first.

### Use Case

Today a file with 200 entries and one mistake fails with, for example:

```
Parsing of vulnlog.yaml failed:
Parser error: Invalid severity: null
```

There is no hint which entry is broken or that "null" means "severity is missing but the
verdict requires one". The user fixes it, reruns, and hits the next error, one at a time.
This is the first experience new users have when hand-editing the YAML, so friendly
errors matter disproportionately.

There is already a TODO in `V1Mapper.toDomain` describing exactly this ("collect
multiple errors and report all back").

### Proposed Solution (optional)

In `V1Mapper.toDomain`, wrap the per-entry mapping in a try/catch that prefixes the
entry ID, collect the messages, and return one `ParseResult.Error` with all of them:

```
Parsing of vulnlog.yaml failed:
vulnerabilities[CVE-2026-0001]: verdict 'affected' requires a severity (low, medium, high, critical)
vulnerabilities[CVE-2026-0417]: invalid justification: 'not applicable'
```

While in there, upgrade the worst messages: "Invalid severity: null" should say the
severity is missing and which values are allowed; same for justification.

### Additional Context (optional)

Found during a code review on the `review` branch (commit f652565). Related issue:
"modify add can write a file that vulnlog itself can no longer parse" - better messages
soften that failure until it is fixed.
