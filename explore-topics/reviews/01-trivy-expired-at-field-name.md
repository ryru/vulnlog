---
name: "Bug Report"
about: Report something that's broken or not working as expected in Vulnlog.
title: "[Bug] Generated .trivyignore.yaml uses expires_at, but Trivy expects expired_at"
labels: bug
assignees: ''
---

### Describe the Bug

Temporary Trivy suppressions never expire. The generated `.trivyignore.yaml` writes the
expiry date under the key `expires_at`, but Trivy's ignore file format uses `expired_at`
(see https://trivy.dev/latest/docs/configuration/filtering/). Trivy does not know the
`expires_at` key, so the suppression is treated as permanent.

This breaks a headline feature: "suppressions can be temporary and expire automatically".

The Kotlin property in `TrivyVulnerabilityEntryDto` is even named `expiredAt`, only the
`@JsonProperty` annotation says `expires_at`.

Where does the problem occur:

- [ ] CLI
- [ ] YAML format
- [x] Suppression output

### Steps to Reproduce

1. Create a Vulnlog file with a Trivy report and a suppression with `expires_at: 2026-08-01`.
2. Run `vulnlog suppress vulnlog.yaml --output-dir out`.
3. Look at `out/.trivyignore.yaml`.

### Expected Behavior

```yaml
vulnerabilities:
- id: CVE-2026-1111
  expired_at: 2026-08-01
  statement: temp suppression while fix pending
```

### Actual Behavior

```yaml
vulnerabilities:
- id: CVE-2026-1111
  expires_at: 2026-08-01
  statement: temp suppression while fix pending
```

Trivy ignores the unknown `expires_at` key, so the finding stays suppressed forever.

### Environment (optional)

- **Version:** built from `review` branch, commit f652565

### Additional Context (optional)

Fix: change the `@JsonProperty` in
`modules/lib/src/main/kotlin/dev/vulnlog/lib/parse/suppression/trivy/dto/TrivyVulnerabilityEntryDto.kt`
from `expires_at` to `expired_at`. Note that the Vulnlog YAML schema itself correctly uses
`expires_at` for its own `suppress` block; only the Trivy output file is affected.
A test asserting the rendered Trivy file content (there is none today) would have caught this.
