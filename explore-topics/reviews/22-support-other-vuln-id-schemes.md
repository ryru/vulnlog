---
name: "Feature Request"
about: Suggest a new feature or enhancement for Vulnlog.
title: "[Feature] Support vulnerability IDs beyond CVE, GHSA, RUSTSEC and SNYK prefixes"
labels: enhancement
assignees: ''
---

### Feature Description

Allow vulnerability IDs (entry `id`, `aliases`, and `reports[].vuln_ids`) that do not
start with one of the four hardcoded prefixes CVE-, GHSA-, RUSTSEC-, SNYK-.

### Use Case

The schema documentation says the ID "may be a scanner-specific ID if no CVE exists",
and the supported reporter list includes scanners whose native IDs use other schemes:
OSV (osv-scanner via reporter `other`), Debian DLA/DSA advisories, Alpine SA, semgrep
rule IDs, dependency-check internal IDs. Today such a file fails hard:

```
Parsing of file.vl.yaml failed:
Parser error: Unsupported vulnerability ID: OSV-2023-1234
```

So a finding that only has an OSV ID cannot be recorded at all, even with
`reporter: other` and a `source:` set.

### Proposed Solution (optional)

Add a catch-all variant, for example `VulnId.Other(id)`, produced by `parseVulnId` when
no known prefix matches. Points to keep in mind:

- Suppression format mapping already filters by ID type (`vulnIdTypes`), so unknown IDs
  would flow into the generic JSON format only; native formats stay unchanged.
- If a completely open ID space feels too loose, an explicit allowlist of further known
  prefixes (OSV-, DLA-, DSA-, ALPINE-) is a smaller first step, but the catch-all avoids
  playing whack-a-mole with scanner ecosystems.

### Additional Context (optional)

Found during a code review on the `review` branch (commit f652565). If the decision is
to keep the closed set, the schema documentation ("may be a scanner-specific ID") and
the parse error message (list the supported prefixes) should be updated instead.
