# Triage Model: re-thinking 'risk acceptable'

Working analysis for issue [#161](https://github.com/vulnlog/vulnlog/issues/161) ("Re-think the
verdict 'risk acceptable' concept"). This is a decision log. It is **not** yet reflected in the
domain model; `devdoc/VEX.md` describes the current model and carries a summary of this planned
change. The issue remains open; the conclusions here are provisional and require further
discussion before they are applied.

Status: reviewed 2026-07-04. CSAF references updated to CSAF 2.1 (OASIS Standard, 2026-02-25),
which changes one supporting argument but not the decisions. See the Review log at the end.

## Background

The current model has three verdicts (`affected`, `not affected`, `risk acceptable`) plus
`under investigation` (the absence of a verdict). In `Verdict.kt`, `Affected` and `RiskAcceptable`
both wrap only a `Severity`; they are structurally identical. `risk acceptable` also requires a
severity and can be combined with `critical`, which is expressible but undesirable.

Oddities raised in #161:

- `risk acceptable` is technically identical to `affected`; only the intent differs.
- `risk acceptable` + `critical` is expressible but undesirable.

A `not affected` verdict is an objective analysis (everyone reaches the same conclusion); severity
is a subjective interpretation. `risk acceptable` is also subjective, but it is a subjective
judgement about **intent**, not about **magnitude**.

## Root cause

`risk acceptable` fuses two orthogonal answers into one verdict slot: **applicability**
("affected") and **intent** ("won't fix"). Triage answers four distinct questions; the current
model collapses two of them, which is why "when do I pick `affected` vs `risk acceptable`?" has no
clean answer.

## The four axes

| Axis        | Question it answers          | Values                                      | Applies when       |
|-------------|------------------------------|---------------------------------------------|--------------------|
| Verdict     | Does it affect this release? | under investigation, not affected, affected | always             |
| Severity    | How severe for us?           | low, medium, high, critical                 | verdict = affected |
| Disposition | What will we do?             | will fix, won't fix (optional, no default)  | verdict = affected |
| Resolution  | Was it remediated, where?    | absent, or { release, at?, ref?, note? }    | always             |

Severity and disposition only carry meaning once the verdict is `affected`. Resolution stays
exactly as it is today (`Resolution.kt`) and remains **independent of the verdict**: it records
the fact that the dependency was updated or the issue otherwise addressed, which also happens for
`not affected` entries as dependency hygiene. The repository's own `vulnlog.yaml` contains such an
entry (the Jackson finding: `not affected` with a resolution in 0.12.0), and the
`VulnerabilityEntry.resolution` documentation states the independence explicitly. An earlier draft
of this table restricted resolution to `affected`; that contradicted the shipped model and data.
VEX derivation reads resolution only when the verdict is `affected` (it decides `fixed` vs
`affected`); for `not affected` entries it changes nothing.

Disposition is **optional with no default**. Its absence means the intent has not been stated,
which is distinct from both `will fix` and `won't fix`. `won't fix` (risk acceptance) is therefore
always an explicit, deliberate choice, never inferred from absence.

### Values: when to use / what each addresses

| Axis        | Value               | When to use / what it addresses                                                                                                                                                                                                   |
|-------------|---------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Verdict     | under investigation | Triage not yet done; no decision recorded. VEX: `under_investigation` / `in_triage`.                                                                                                                                              |
| Verdict     | not affected        | The vulnerability does not affect this release. Requires a justification. VEX: `not_affected`.                                                                                                                                    |
| Verdict     | affected            | The vulnerability affects this release. Carries a severity. VEX: `affected` / `exploitable`.                                                                                                                                      |
| Severity    | low ... critical    | The project's **own** impact assessment for this release, not the upstream CVSS. Magnitude only. CycloneDX `ratings[]`.                                                                                                           |
| Disposition | will fix            | The project intends to remediate. CycloneDX `update`; CSAF 2.1 `fix_planned` (unreleased) / `vendor_fix` (released); OpenVEX text.                                                                                                |
| Disposition | won't fix           | The project accepts the risk; no remediation intended (the old `risk acceptable`). CycloneDX `will_not_fix`; CSAF `no_fix_planned`.                                                                                               |
| Disposition | (absent)            | Intent not stated. VEX writers emit no `response`/remediation; absence is never synthesised as `will fix`.                                                                                                                        |
| Resolution  | absent              | Not yet remediated.                                                                                                                                                                                                               |
| Resolution  | present             | The release/date/ticket where the issue was addressed. Drives VEX `fixed`/`resolved` when target >= resolution release and verdict is affected. Coexists with `won't fix` (passive fix) and with `not affected` (hygiene update). |

### Valid combinations and mapping from the old model

| Verdict             | Severity      | Disposition | Resolution | Meaning                                         | Old model                 |
|---------------------|---------------|-------------|------------|-------------------------------------------------|---------------------------|
| under investigation | -             | -           | -          | Not yet triaged                                 | (verdict absent)          |
| not affected        | -             | -           | absent     | Does not apply (with justification)             | not affected              |
| not affected        | -             | -           | present    | Does not apply; dependency updated anyway       | not affected + resolution |
| affected            | low ... crit. | (absent)    | absent     | Affected, intent not stated                     | affected                  |
| affected            | low ... crit. | (absent)    | present    | Affected, fixed in release X                    | affected + resolution     |
| affected            | low ... crit. | will fix    | absent     | Affected, fix intended, not yet done            | (new)                     |
| affected            | low ... crit. | will fix    | present    | Affected, fix intended, fixed in release X      | (new)                     |
| affected            | low ... crit. | won't fix   | absent     | Affected, risk accepted                         | risk acceptable           |
| affected            | low ... crit. | won't fix   | present    | Risk accepted, but passively fixed in release X | risk acceptable + resol.  |

Severity and disposition with `under investigation` or `not affected` are invalid (see Validation
rules).

### YAML examples

```yaml
# Risk accepted, no fix planned (the old 'risk acceptable')
verdict: affected
severity: low
disposition: wont-fix

# Fix intended but not yet shipped
verdict: affected
severity: high
disposition: will-fix

# Accepted, later passively fixed by an unrelated dependency bump
verdict: affected
severity: low
disposition: wont-fix
resolution:
  in: 0.12.0
  note: Update ktlint to 14.2.0 also updates logback to 1.3.14

# Intent not stated (plain affected, unchanged from today)
verdict: affected
severity: medium
```

## Why not the alternatives

**Severity value (the #161 proposal).** Adding `risk_acceptable` to the severity enum conflates
magnitude with intent and makes them mutually exclusive: "we accept this HIGH-severity risk"
becomes inexpressible. It also degrades the VEX `ratings[]` mapping: an accepted vuln would have no
magnitude to emit, which is the most valuable case. And it breaks the ordinal scale: `Severity` is
a magnitude ranking (`low` to `critical`, `Severity.kt`); `risk_acceptable` is not a magnitude and
has no defensible position relative to the others.

**Resolution.** Resolution is a **fact of remediation** (release/date/ref/note, `Resolution.kt`).
`won't fix` is a **decision not to remediate**. The "accepted but fixed anyway" case requires both
to coexist (a later release passively fixes an accepted vuln). Folding acceptance into resolution
would make them mutually exclusive, which is wrong.

## Disposition reduced to two values

Decision: `disposition` is one of `will fix`, `won't fix`.

A finer gradient (e.g. `won't fix` / `fix not planned` / `will fix`) was considered and rejected:
**no VEX format preserves the `won't fix` vs `fix not planned` distinction**. CycloneDX pushes both
to `will_not_fix`, CSAF folds both into `no_fix_planned` (unchanged in CSAF 2.1), OpenVEX expresses
neither structurally. A third value would add human nuance at zero VEX fidelity.

Update from the CSAF 2.1 review: the original rationale also noted that only `won't fix` had a
crisp native target in both structured formats. CSAF 2.1 adds `fix_planned`, so `will fix` now has
a crisp CSAF target too (`fix_planned` while unreleased, `vendor_fix` once released). This
strengthens keeping `will fix` and leaves the two-value decision unchanged.

## VEX mapping impact

| Disposition | OpenVEX 0.2                     | CycloneDX 1.7 `response[]` | CSAF 2.1 `remediations.category`                     |
|-------------|---------------------------------|----------------------------|------------------------------------------------------|
| will fix    | `action_statement` text         | `update`                   | `fix_planned` (unreleased) / `vendor_fix` (released) |
| won't fix   | `action_statement` text         | `will_not_fix`             | `no_fix_planned`                                     |
| (absent)    | `action_statement` default text | omitted                    | `none_available`                                     |

Notes:

- **OpenVEX 0.2 has no structured intent axis.** Disposition survives only as free-text
  `action_statement`; a machine consumer cannot read it. Note that OpenVEX **requires** an
  `action_statement` for every `affected` statement, so even an absent disposition needs a default
  text (see the action-statement derivation in `VEX.md`).
- **CycloneDX** carries both endpoints cleanly. The passive-fix case (`won't fix` + a later
  resolution release) maps to `["will_not_fix", "update"]`.
- **CSAF 2.1** matches both values: `won't fix` to `no_fix_planned`, `will fix` to `fix_planned` /
  `vendor_fix`. The CSAF VEX profile requires a remediation entry for `known_affected` products,
  so an absent disposition emits `none_available`. (Under CSAF 2.0 an unreleased fix degraded to
  `none_available`; 2.1 removes that loss.)

### Status derivation impact (behavior change)

Disposition never influences the VEX status; status derives from verdict + resolution vs target
release. Removing the `risk acceptable` verdict therefore changes emitted statuses for passively
fixed accepted vulnerabilities:

| Case                                                     | Old model status (OpenVEX / CycloneDX) | New model status                       |
|----------------------------------------------------------|----------------------------------------|----------------------------------------|
| risk accepted, no resolution                             | `affected` / `exploitable`             | `affected` / `exploitable` (unchanged) |
| risk accepted, fix in a later release, target before fix | `affected` / `exploitable`             | `affected` / `exploitable` (unchanged) |
| risk accepted, fix contained in target                   | `affected` / `exploitable`             | `fixed` / `resolved` (**changed**)     |

Example from `vulnlog.yaml`: CVE-2023-6481 (`risk acceptable`, resolution in 0.12.0). For target
0.12.0 the old model emits `exploitable` forever; the new model emits `resolved`. The new output is
more correct: consumers get positive fixed assurance instead of a permanently open finding.

### Response derivation (new model)

Replaces the verdict-shape inference in `VEX.md` once #161 lands. Derives from disposition +
resolution:

| State (verdict + resolution vs target) | Disposition                        | `response[]`                 |
|----------------------------------------|------------------------------------|------------------------------|
| `resolved` (fix contained in target)   | any or absent                      | `["update"]`                 |
| `exploitable`                          | won't fix, no resolution           | `["will_not_fix"]`           |
| `exploitable`                          | won't fix, resolution after target | `["will_not_fix", "update"]` |
| `exploitable`                          | will fix (any resolution)          | `["update"]`                 |
| `exploitable`                          | absent, resolution after target    | `["update"]`                 |
| `exploitable`                          | absent, no resolution              | omitted                      |
| `not_affected` / `in_triage`           | any                                | omitted                      |

## Validation rules

- `disposition` is only valid when `verdict: affected`; any other verdict with a disposition is a
  validation error. Hygiene updates on `not affected` entries are expressed as `resolution`, not as
  disposition; intent about remediation is meaningless when nothing affects the release.
- `severity` remains required exactly when `verdict: affected` (unchanged rule, now covering the
  former risk-acceptable entries).
- `wont-fix` + `critical` is allowed; no constraint or hard error (decision 3). An optional
  `vulnlog validate` hint is possible but not required.
- `resolution` remains valid with any verdict (unchanged).

## Decisions (from the #161 discussion)

1. **Disposition values.** `will fix` / `won't fix`. `won't fix` replaces the old `risk acceptable`
   and has crisp native targets (`will_not_fix` / `no_fix_planned`). `will fix` maps to CycloneDX
   `update` and, since CSAF 2.1, to `fix_planned` / `vendor_fix`.
2. **Optional, no default.** The disposition field is optional and has no default. Absence means the
   intent is not stated. `won't fix` is always explicit; risk acceptance is opt-in, never inferred.
   VEX writers omit `response`/remediation when disposition is absent and must not synthesise
   `will fix`.
3. **`won't fix` + `critical` is allowed.** Uncommon but valid; no constraint or hard error. A
   validation hint is optional, not required.
4. **YAML carrier.** A single optional `disposition` key on the vulnerability entry (not required).
   The name `disposition` is preferred over `response` (a CycloneDX-specific term); the YAML-addition
   list in `VEX.md` uses this name. Tokens: `will-fix` / `wont-fix`.

   ```yaml
   verdict: affected
   severity: high
   disposition: wont-fix    # optional; omit when intent is unstated
   ```
5. **Migration.** `risk acceptable` becomes `affected` + `disposition: wont-fix`. Existing
   `affected` entries migrate to `affected` with **no** disposition (intent unstated), not to
   `will fix`.

## Migration mechanics

Concrete path for decision 5, following the project policy that all writing commands rewrite files
canonically:

1. **Parser.** Accept the legacy `verdict: risk acceptable` token during a deprecation window and
   map it to `affected` + `disposition: wont-fix` (severity carries over unchanged). Print a
   deprecation warning naming the entry id.
2. **Canonical writes.** Any writing command (`fmt`, `add`, `copy`, `suppress`, ...) emits the new
   form, so a single `vulnlog fmt` migrates a file in place.
3. **JSON schema.** Add the optional `disposition` key (enum `will-fix`, `wont-fix`); keep
   `risk acceptable` in the verdict enum during the window with a deprecation note in its
   description, then remove it.
4. **Reporting.** `affected` + `wont-fix` without resolution maps to `WorkState.DISMISSED`, with
   resolution to `RESOLVED`, reproducing current behavior (`Reporting.kt:100-101`). Whether
   `Impact.AcceptableRisk` (`Impact.kt:15`) stays as a derived value or collapses into `Affected`
   is open (see Open questions).
5. **Docs.** Update `verdicts-and-justifications.adoc`, `vulnerability-states.adoc`, and
   `migration-guide.adoc`. CHANGELOG comes from git-cliff via the commit messages.
6. **Window length.** Open: number of releases the legacy token stays accepted, and whether its
   removal is tied to a specific minor version.

## Open questions

- **HTML report grouping/sorting** once `risk acceptable` is no longer a verdict. The report
  already supports the concept: `WorkState.DISMISSED` houses both `NotAffected` and
  `RiskAcceptable` when no resolution is present, and a dedicated `Impact.AcceptableRisk` exists
  (`Reporting.kt:100-101`, `Impact.kt:15`). So `affected + won't fix` -> `DISMISSED` reproduces
  current behavior (with a resolution it is `RESOLVED`). Still open: whether to keep
  `Impact.AcceptableRisk` (derived from `affected + won't fix`) or collapse it into `Affected`,
  and the bucket for affected entries with no stated disposition (-> `OPEN`).
- **Kotlin model shape**: a `Disposition` enum carried as a nullable field on the entry, vs.
  extending `Verdict.Affected`. `Verdict.RiskAcceptable` is removed either way.
- **Migration window length** and the release that drops the legacy token (see Migration
  mechanics, item 6).
- **Validate hint** for `wont-fix` + `critical`: ship it or skip it.

## Status

Issue #161 open. Core model agreed (four axes; two-value optional disposition; `won't fix` replaces
`risk acceptable`). This review added validation rules, migration mechanics, the status-derivation
impact, and the concrete response table; naming and report details remain open. The domain model is
unchanged; `VEX.md` summarizes this change under "Planned model change (issue #161)".

## Inputs / references

- Issue [#161](https://github.com/vulnlog/vulnlog/issues/161): re-think 'risk acceptable'.
- `devdoc/VEX.md`: VEX generation plan and format mappings (status/response/ratings derivation).
- Domain model: `modules/lib/src/main/kotlin/dev/vulnlog/lib/model/{Verdict,Severity,Resolution}.kt`.
- [CSAF 2.1 OASIS Standard](https://docs.oasis-open.org/csaf/csaf/v2.1/csaf-v2.1.html) (2026-02-25),
  remediation category enum incl. `fix_planned` and `optional_patch`;
  [CSAF 2.0](https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html) for the previous
  five-value enum (`vendor_fix`, `no_fix_planned`, `none_available`, `mitigation`, `workaround`).
- [CycloneDX 1.7 JSON schema](https://github.com/CycloneDX/specification/blob/master/schema/bom-1.7.schema.json),
  `response` enum: `update`, `will_not_fix`, `can_not_fix`, `rollback`, `workaround_available`
  (verified identical to 1.6 on 2026-07-04).
- [OpenVEX v0.2.0](https://github.com/openvex/spec/blob/main/OPENVEX-SPEC.md): no structured intent
  enum; `action_statement` only, and required for `affected` statements.

## Review log (2026-07-04)

1. **CSAF updated to 2.1** (OASIS Standard, 2026-02-25). New `fix_planned` category gives
   `will fix` a crisp CSAF target; the earlier claim that an unreleased fix degrades to
   `none_available` now applies only to CSAF 2.0. The two-value disposition decision is unchanged
   because the `won't fix` vs `fix not planned` distinction still collapses in every format.
2. **Resolution axis corrected.** The four-axes table restricted resolution to
   `verdict = affected`; that contradicted the shipped model (`VulnerabilityEntry.resolution` is
   documented as verdict-independent) and shipped data (the Jackson entry in `vulnlog.yaml` is
   `not affected` with a resolution). Resolution now applies always; VEX reads it only for
   `affected`.
3. **Validation rules added** (disposition requires `affected`; severity requirement unchanged;
   `wont-fix` + `critical` allowed).
4. **Migration mechanics added** (parser window, canonical rewrite, JSON schema handling, report
   mapping, docs).
5. **Status-derivation impact documented**: passively fixed accepted vulnerabilities flip from
   `exploitable` to `resolved` for targets containing the fix, with CVE-2023-6481 as the concrete
   example.
6. **Response derivation concretized** into a table (was an open bullet).
7. **Mapping table gains the absent-disposition row** (OpenVEX still requires a default
   `action_statement`; CSAF requires `none_available`).
8. YAML examples added; ASCII-only cleanup.
