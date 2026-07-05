# Local issue drafts from the 2026-07-04 code review

One file per topic, each following the repository issue templates
(`.github/ISSUE_TEMPLATE/`). Drafted locally for later submission as GitHub issues;
nothing has been created online. Reviewed at commit f652565 (`review` branch).
Findings marked "verified" were reproduced with a locally built CLI.

## Bugs

| # | File | Title | Verified |
|---|------|-------|----------|
| 01 | 01-trivy-expired-at-field-name.md | Trivy ignore file writes `expires_at`, Trivy expects `expired_at`; temporary suppressions never expire | yes + Trivy docs |
| 02 | 02-snyk-expires-format-and-version.md | `.snyk` `expires` needs full ISO datetime, `version` field missing; ignores never expire | yes + Snyk docs |
| 03 | 03-unknown-yaml-fields-silently-dropped.md | Misspelled/unknown YAML fields pass validation and are silently deleted on rewrite | yes |
| 04 | 04-add-writes-unparseable-file.md | `modify add --verdict affected` without severity writes a file vulnlog cannot parse anymore | yes |
| 05 | 05-name-field-lost.md | `name` never reaches reports and is deleted by `modify copy` | yes |
| 06 | 06-vuln-id-case-sensitivity.md | `cve-...` and `CVE-...` become two entries; duplicates not flagged | yes |
| 07 | 07-resolution-release-not-validated.md | `resolution.in` accepts undefined releases | yes |
| 08 | 08-yaml-syntax-error-stacktrace.md | YAML syntax errors crash with a raw stack trace | yes |
| 09 | 09-copy-crash-no-releases.md | `modify copy` crashes when the target has no releases | yes |
| 10 | 10-html-report-script-injection.md | `</script>` in text fields breaks the HTML report and allows script injection | yes |
| 11 | 11-suppress-silently-drops-mismatched-ids.md | suppress silently drops entries whose ID type does not fit the format (empty `.snyk`) | yes |
| 12 | 12-gradle-suppress-ignores-current-date.md | Gradle `vulnlogSuppress` up-to-date/cache ignores the current date; expired suppressions persist | code review |
| 13 | 13-report-filter-first-file-only.md | report filters resolved against the first input file only | code review |
| 14 | 14-published-at-never-used.md | Docs promise `published_at` semantics that are not implemented (+ copy help typo) | code review |
| 15 | 15-init-overwrites-existing-file.md | `init` overwrites an existing file without asking | yes |
| 16 | 16-validation-message-internal-representation.md | Findings print `Release(value=1.0.0)` instead of `1.0.0` | yes |
| 17 | 17-generic-suppression-filename-underscore.md | Generic suppression file named `github_dependabot.generic.json` instead of kebab-case | yes |
| 18 | 18-verdict-under-investigation-schema-mismatch.md | `verdict: under_investigation` accepted by CLI, invalid per JSON schema | yes |
| 19 | 19-schema-analysis-description-wrong.md | Schema says `analysis` changes the state; it does not | code review |

## Enhancements

| # | File | Title |
|---|------|-------|
| 20 | 20-validate-release-chronological-order.md | Warn when releases are not chronological (silently wrong `--release` filtering, verified) |
| 21 | 21-parse-errors-lack-context.md | Parse errors should name the entry and report all problems at once |
| 22 | 22-support-other-vuln-id-schemes.md | Support IDs beyond CVE/GHSA/RUSTSEC/SNYK prefixes (OSV etc.) |
| 23 | 23-core-add-uses-wall-clock.md | core Add: inject the current date instead of `LocalDate.now()` |

## Suggested order

The two scanner-format bugs (01, 02) undermine the advertised auto-expiry feature and
are one-line to small fixes. The silent data-loss group (03, 04, 05, 15) protects user
data. 06 to 11 are correctness and robustness. The rest is polish and consistency.
Cross-cutting suggestion from 01/02: add golden tests for the rendered Trivy and Snyk
files, which currently do not exist and would have caught both format bugs.
