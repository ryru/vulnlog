# JSON Schema Review

Status: review notes, 2026-07-04, at commit f652565. Scope: `schema/v1/` and
the bundled `schema/vulnlog-v1.json`.

## Method and baseline checks

Ran the project's own tooling (see `JSON-Schema.md`) plus example validation:

- `metaschema` on the bundle: pass.
- `lint` on `schema/`: only cross-file resolution noise and orphan-`$defs`
  false positives for `common.json` (its defs are referenced from other
  files); no real findings.
- Bundle freshness: re-bundled `v1/vulnlog.json` and diffed against
  `vulnlog-v1.json`: byte-identical, in sync.
- All embedded `examples` (top level and vulnerability) validate against
  their schemas, including the verdict conditionals.

The conditional logic itself is sound: severity is required for
`affected`/`risk acceptable`, justification is required for `not affected`
and forbidden otherwise. The schema is strict (`additionalProperties: false`
throughout), well documented, and split cleanly into defs. The findings below
are refinements, not structural problems.

## Findings

### 1. `report.json`: `if` condition matches when `reporter` is absent

The conditional lacks `required` in the `if`:

```json
"if": { "properties": { "reporter": { "const": "other" } } }
```

`properties` is vacuous for absent members, so an entry without `reporter`
matches the condition and the `then` fires: the validator reports both
"reporter is required" and a misleading "source is required". The three
conditionals in `vulnerability.json` all include `"required": [ "reporter" ]`
correctly; this one should too. Low impact, one-line fix.

### 2. `common.json` date pattern accepts impossible dates

`^\d{4}-\d{2}-\d{2}$` accepts `2026-13-45`, `2026-00-00`, and `2026-02-30`
(verified). Suggested fix, twofold:

- Add `"format": "date"`. It is annotation-only in 2020-12 by default but
  editors and format-asserting validators use it.
- Tighten the pattern to `^\d{4}-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])$`.
  Day-per-month precision is not worth regex complexity; the CLI parses with
  `LocalDate` and catches the rest.

### 3. `common.json` purl pattern accepts empty and whitespace remainders

`^pkg:[a-zA-Z][a-zA-Z0-9.+-]*/` matches `pkg:npm/` (nothing after the slash)
and `pkg:npm/lib with spaces` (verified). Suggested:
`^pkg:[a-zA-Z][a-zA-Z0-9.+-]*/[^\s]+$`. Still a heuristic; packageurl-java in
the CLI remains the real validator.

### 4. `severity` is allowed where the domain silently drops it

`justification` is actively forbidden unless the verdict is `not affected`
(third `allOf` clause), but `severity` has no mirror rule: the schema accepts
`severity` on a `not affected` entry or on an entry without verdict. The
domain model carries severity only inside `Affected` and `RiskAcceptable`
(`V1Mapper` ignores it otherwise), so a canonical rewrite deletes the field
without a message. Same data-loss class as the `name` field (issue #192).
Suggested: add the mirror conditional so the schema forbids what the code
discards, or decide that severity is meaningful pre-verdict and keep it in
the domain. Either way, schema and code must agree.

### 5. `analyzed_at` without `analysis` is accepted

An analysis date with no analysis text is almost certainly an authoring
mistake. One line fixes it in `vulnerability.json`:

```json
"dependentRequired": { "analyzed_at": [ "analysis" ] }
```

### 6. Missing `uniqueItems` on identifier arrays

None of the string arrays declare `uniqueItems: true`:
`vulnerability.releases`, `vulnerability.tags`, `aliases`, `packages`,
`reports[].vuln_ids`, and `release.purls[].tags`. Duplicates in these arrays
are always author errors and the keyword is free. (Uniqueness across entries,
e.g. vulnerability ids file-wide, is not expressible in JSON Schema and
stays a CLI validation concern.)

### 7. Inconsistent `minLength` on free-text fields

`description` (vulnerability) and `source` (report) declare `minLength: 1`,
while `analysis`, `comment`, `resolution.note`, and `tag.description` accept
the empty string. Unify on `minLength: 1` for all free-text fields; an empty
analysis is indistinguishable from noise.

### 8. `format: "email"` and `format: "uri"` are annotation-only

In draft 2020-12, `format` does not assert by default, so `contact:
"not-an-email"` passes most validators. Acceptable if understood; if
enforcement is wanted, the CLI has to do it (or a modest pattern is added).
Worth a sentence in the docs so nobody relies on the schema here.

### 9. Behavioral claims in descriptions drift from the code

Two are already proven wrong: the `analysis` description claims presence
changes the entry state (issue #206), and `published_at` promises semantics
the code never reads (issue #201). The `suppressEntry` description encodes
the full suppression decision table and is correct today, but it is the same
risk category. Suggestion: keep field descriptions about the data ("what this
field means") and link behavior to the docs site, which is versioned with the
code. At minimum, treat descriptions as assertions to check when the
behavior changes.

### 10. Schema and CLI disagree about what is valid (tracked)

Listed for completeness; all have issues already:

- `verdict: under_investigation` parses in the CLI but is invalid per schema
  (#205).
- The CLI ignores unknown fields that the schema rejects, so editor
  validation and `vulnlog validate` disagree (#190).
- The CLI constrains id prefixes (CVE, GHSA, RUSTSEC, SNYK) and is
  case-sensitive; the schema only requires a non-empty string (#209, #193).

The direction should be: the published schema is the contract, the CLI
matches it exactly. Any divergence in either direction is a bug.

### 11. Constraints only prose can hold (accepted limitation)

Cross-references (`releases`, `tags`, `resolution.in` must point to defined
ids), file-wide id/alias uniqueness, and chronological release order cannot
be expressed in JSON Schema. The descriptions document them well. The CLI
owns enforcement; #194 (resolution.in unchecked) and #207 (chronological
order warning) cover the current gaps.

## Recommendations

Priority order:

1. Fix the `report.json` `if` (finding 1) and the description of `analysis`
   (#206): both are small and user-visible in editors.
2. Add `dependentRequired`, `uniqueItems`, the severity mirror rule, and the
   `minLength` unification (findings 4 to 7) in one schema patch; they change
   validity only for files that are already mistakes.
3. Tighten the date and purl patterns (findings 2 and 3).
4. Automate what is currently manual in `JSON-Schema.md`: run `metaschema`,
   `lint`, a bundle-freshness diff, and validation of all embedded examples
   plus the docs example files in CI. The bundle being in sync today is luck,
   not process.

Since `additionalProperties: false` makes every new field a breaking change
for old validators, batch schema additions and note them in the changelog;
the `schemaVersion` const gives a clean escape hatch when v2 becomes
necessary (see `Multi-File.md`, which already needs it for imports).
