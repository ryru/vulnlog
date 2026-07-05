# Multi-File Support

Design analysis for [issue #132](https://github.com/vulnlog/vulnlog/issues/132), written 2026-07-04. Status:
brainstorm with a phased recommendation, nothing here is decided.

## Context

Issue #132 proposes splitting the single Vulnlog YAML into multiple files. It names three use cases:

1. Separate static information (project, releases, tags) from dynamic information (vulnerabilities).
2. Split vulnerabilities by domain, for example dev/build dependencies vs production dependencies, or by team
   ownership, instead of using tags.
3. A vulnerability-per-file approach where one vulnerability is referenced from multiple Vulnlog files,
   probably requiring an override mechanism.

A fourth motivation comes from users of the branching strategies: with one Vulnlog file per release branch
(sequential releases, easy archiving), engineers must add the same CVE to several files. That is tedious and
duplicates content.

What exists today:

- Three documented branching strategies (`docs/modules/ROOT/pages/branching-strategy.adoc`): single-file,
  multi-file (one file per release branch, all files on the main branch), and per-branch (the file lives on
  each release branch). The documented answer to duplication is `vulnlog modify copy`
  (`docs/modules/ROOT/pages/migration-guide.adoc`, section "What about duplication?").
- Multi-file already exists at the invocation level: `validate`, `fmt`, and `report` accept multiple
  positional files (`modules/lib/src/main/kotlin/dev/vulnlog/lib/shell/ParseFile.kt`). Each file is a
  self-contained document. `report` merges documents that share identical project metadata
  (`modules/lib/src/main/kotlin/dev/vulnlog/lib/core/Reporting.kt`), keeping conflicting verdicts as separate
  rows. `suppress` takes exactly one file (CLI positional and Gradle `requireSingleVulnlogFile`).
- `modify add` fans one new entry out to N destination files. `modify copy` propagates existing entries from
  one file into N destination files (`modules/lib/src/main/kotlin/dev/vulnlog/lib/core/Copy.kt`).

Issue #132 therefore asks for a new, third thing: composing one logical document out of several files. That
is intra-document composition, below the existing inter-document merge of `report`. The two layers must stay
distinct: merging two branch files into one document would turn legitimately different per-branch verdicts
into duplicate-ID errors.

## Constraints From the Codebase

These facts shape every design below.

1. **The version gate is major-only, and unknown keys are dropped silently.**
   `modules/lib/src/main/kotlin/dev/vulnlog/lib/parse/YamlParser.kt` dispatches on `schemaVersion.major`
   only, and the mapper (`modules/lib/src/main/kotlin/dev/vulnlog/lib/parse/YamlMapperFactory.kt`) does not
   fail on unknown properties (`local-issues/03`). If `imports:` were added under schema version "1" or
   "1.1", every already shipped CLI would parse such a file successfully and silently ignore the key:
   `validate` reports OK, `report` and `suppress` silently miss all imported vulnerabilities, and `fmt`,
   `modify add`, and `modify copy` rewrite the whole file from the DTO and physically delete the `imports:`
   key from disk. Only an unsupported major version produces a hard error ("Unsupported schema version '2'.
   Try updating vulnlog."). Consequence: any file that uses imports must carry `schemaVersion: "2"`.
2. **Fragment files are doubly invalid today.** The DTO requires `schemaVersion`, `project`, `releases`, and
   `vulnerabilities` (`modules/lib/src/main/kotlin/dev/vulnlog/lib/parse/v1/dto/VulnlogFileV1Dto.kt`), and
   the published JSON schema requires the same keys with `additionalProperties: false`
   (`schema/v1/vulnlog.json`). A file containing only `vulnerabilities:` needs its own DTO, its own
   published schema, and an IDE association story.
3. **Release order is semantic.** `--release` filtering includes all releases up to and including the given
   one, based on array position (`modules/lib/src/main/kotlin/dev/vulnlog/lib/shell/FilterValidation.kt`,
   `take(index + 1)`). Concatenating `releases:` arrays across files in import order can silently corrupt
   range filters, and chronological order is not validated yet (`local-issues/20`).
4. **Gradle up-to-date checking needs declared inputs.** `VulnlogValidateTask` and `VulnlogReportTask` are
   cacheable tasks with `@InputFiles files`. Imports resolved only at parse time would leave fragment edits
   invisible to Gradle: the task stays UP-TO-DATE and replays "validation OK" on stale data. Import
   expansion into declared task inputs (for example via a configuration-cache-safe `ValueSource`) is
   mandatory scope for any import design, not a follow-up.
5. **Strict concatenation cannot share vulnerability entries across branch documents.** Every entry's
   `releases` must reference releases defined in the same document
   (`modules/lib/src/main/kotlin/dev/vulnlog/lib/core/Validator.kt`), the schema requires at least one
   release per entry, and verdicts legitimately differ per branch (migration-guide, "Conflicting
   verdicts"). A shared vulnerabilities fragment imported by two branch main files would dangle in at least
   one of them. Also, imports cannot cross git branches at all: a fragment on the main branch is invisible
   to a checkout of `release/1.x`. Only tooling or cherry-picking helps the per-branch strategy.
6. **Copy is the current merge-semantics prototype, and it shows the subtlety.** `Copy.kt` rewrites every
   copied entry's releases to the destination's latest release (`destination.releases.last()`), merges
   existing entries with existing-scalar-wins plus list-union rules, and crashes on a destination with
   `releases: []` (`local-issues/09`). The `report` filter is resolved against the first file only
   (`local-issues/13`). Both bugs sit exactly where multi-file work would build.

## Solution Designs

### A: `imports:` in the main file, concatenation, duplicate IDs are errors

The issue sketch: the main file (passed to the CLI) lists imported files; imported files contribute
tags/releases/vulnerabilities; arrays are concatenated; duplicate IDs across files are errors; paths are
relative to the importing file; no recursion; the CLI signature stays unchanged.

Serves: use cases 1 and 2 fully. Use case 3: no, ruled out by the duplicate-ID error. Branch pain: no
(constraint 5), except trivially sharing a tags fragment.

Pros:

- The composition is recorded in git, in the data itself. CI, the local CLI, the IDE, and a human reading
  the repository all see the same document boundary. This matches the project values (checked-in static
  config, git YAML as the immutable core).
- CLI and CI surfaces stay unchanged. `suppress vulnlog.yaml` in existing pipelines keeps working, and
  `suppress` gains multi-file coverage it structurally lacks today: a repository split per use case 2
  cannot generate combined suppressions at all right now; with imports it can, through the one main file.
- Deterministic and idempotent: concatenate in `imports:` order, error on duplicate IDs naming both files.
  The merge is a pure `core` function; file reading stays in `shell` (fits `devdoc/Architecture.md`).
- Minimal schema delta when scoped tightly: one optional `imports` key plus a fragment schema. No override
  DSL, no new entry fields.

Cons and gotchas:

- Forces `schemaVersion: "2"` (constraint 1), a published `vulnlog-v2.json`, a fragment schema, and updates
  to the hand-maintained schema bundling.
- Recommended deviations from the sketch: fragments should also carry `schemaVersion` (self-describing,
  hard failure on old CLIs, allows direct `fmt`/`validate` of a fragment; a fragment is distinguished from
  a document by the absent `project` key), and fragments should hold `vulnerabilities` and `tags` only, no
  `releases` (constraint 3) and no nested imports (depth 1).
- Provenance is a prerequisite: neither DTO nor domain model records a source file today. Needed for
  file-qualified validation findings, for write routing, and for reporting which files form the document.
- Write routing must be defined: `modify add` and `modify copy` upsert into one file's raw DTO and rewrite
  that file. Rule proposal: update in place wherever the ID already lives; new entries go to the main file;
  an explicit `--into <fragment>` targets a fragment. No magic defaults.
- `fmt` must format each member file separately and must never materialize the merged document into one
  file.
- Path policy: relative paths only, existing filename rules
  (`modules/lib/src/main/kotlin/dev/vulnlog/lib/shell/InputValidation.kt`), no absolute paths, no `..`
  escapes, deduplicate by canonical path, reject imports when the main document comes from stdin.
- Shell glob trap: `vulnlog validate *.vl.yaml` would feed fragments in as standalone documents. Fragments
  must be recognized and handled gracefully, or get a distinct suffix (see open questions).
- Gradle input expansion (constraint 4) is part of the same release.

Impact: the largest format change since the YAML migration. Touches `lib/parse` (v2 DTOs, fragment DTO,
fragment writer, version dispatch), `lib/shell` (import resolution), `lib/model` (document and provenance
types), `lib/core` (pure compose plus cross-file validation), `cli-app`, `gradle-plugin`, `schema/`, and the
user docs.

### B: Invocation-level merge, no imports key

Pass N files (or a directory, or a `vulnlog.d/` convention) and merge them into one logical document.
Exactly one file carries `project`.

Serves: nominally use cases 1 and 2. Branch pain: no.

Pros:

- No schema change, no version bump, no fragment schema, no path security questions.
- Gradle-native: an explicit file collection is a declared input, so constraint 4 disappears.

Cons and gotchas:

- Disqualifying conflict: today N positional files are N independent documents for `validate`/`fmt` and N
  same-project documents for `report`, and the documented multi-file branching strategy tells users to
  invoke exactly that way. Under B, `validate a.vl.yaml b.vl.yaml` would suddenly merge two branch files
  into one document and produce duplicate-ID errors for legitimately differing per-branch verdicts. B
  conflates fragments-of-one-document with documents-of-one-project, a distinction the codebase
  deliberately maintains.
- Document identity depends on the invocation, not on the data. CI arguments, local arguments, and Gradle
  configuration can silently disagree. Nothing in git records what the document is. This is the opposite of
  the checked-in-config value.
- An opt-in variant (a `--merge` flag or a `vulnlog.d/` directory) removes the breakage but keeps the
  identity problem and still needs almost all of A's machinery (fragment parsing, provenance, write
  routing, per-command semantics). Roughly A's cost minus the schema work, for less value.

### C: Vulnerability-per-file, shared finding plus per-document override

Use case 3. Shared finding data (ID, aliases, description, packages, reports) is written once; each document
references it and overrides document-specific fields (releases, verdict, analysis, resolution).

Serves: use case 3 by construction. Branch pain: partially for the multi-file-on-main strategy; no for the
per-branch strategy (constraint 5: files on other git branches are unreachable, the shared file itself would
need cherry-picking, which is today's problem relocated).

Pros:

- The only design that de-duplicates finding data across documents. Later edits (a new alias, a report
  date) happen once. One small file per vulnerability also merges more cleanly in git.

Cons and gotchas:

- What it saves is small relative to its cost. The per-document stub still needs releases, verdict,
  severity or justification, analysis, and resolution, which is most of what a human writes. Initial
  propagation is already a one-liner via `modify add`/`modify copy`.
- Deep-merge semantics move from an explicit command (run once, visible in the diff) into every read of
  every file (invisible, permanent). The `Copy.kt` merge table shows how subtle this gets, and it already
  produced a crash (`local-issues/09`). Files stop being self-contained, which works against the format's
  core promise (compact, readable, a natural archive).
- Canonical writes must become layer-aware: `fmt`/`add`/`copy` must not materialize inherited fields into
  stubs and must route each written field to the right layer. `suppress` derives from verdicts, so the
  merge lands in the read path of the most security-critical output.
- Needs dual entry schemas (a stub without packages/reports, a shared finding without releases), plus
  garbage-collection validation for unreferenced findings. File explosion multiplies the Gradle input
  problem.

Impact: everything in A plus a merge-semantics specification, dual schemas, and layer-aware writers. Roughly
twice A.

### D: No format change, tooling only

Fix and extend the existing propagation tooling: fix the copy crash (`local-issues/09`) and the report
filter (`local-issues/13`), add `modify copy --release <id>` (today copy hard-rewrites the entry to the
destination's latest release, which is wrong whenever the CVE affects an older shipped release), and add a
read-only `vulnlog diff <file...>` that prints a vulnerability-by-file matrix (presence plus verdict deltas).

Serves: the branch pain point on both strategies, and for the per-branch strategy it is the only design that
helps at all (combined with the already documented git worktree workflow, since the CLI happily takes paths
into other worktrees). Use cases 1 to 3: not at all.

Honest assessment: D gets surprisingly far on the stated pain. Adding a new CVE to N files on main is
already one command (`modify add f1 f2 f3 ...`). Propagating an analyzed entry is one command after the
`--release` fix. The remaining gap is awareness (nothing tells you which files miss an entry), which
`vulnlog diff` closes, and which doubles as review tooling for whatever multi-file design comes later. A
write-mode `sync` command is copy-in-a-loop and can wait.

Cons: repeated finding data stays repeated (tool-assisted, not eliminated), and per-branch propagation still
means one commit per branch, which is inherent to git and no file format can fix.

Impact: small. Crash fix, one option on copy, one new read-only command built as a pure core function.

### E: Fixed two-file split

Main file plus exactly one vulnerabilities file. Solves use case 1 only, yet needs about 80 percent of A's
infrastructure (fragment DTO and schema, provenance, write routing, Gradle inputs, the v2 gate). The saved
part (N-way import lists, cross-fragment duplicate checks) is the cheap part. Not worth being a separate
design; its useful insight survives as the scope cap on A (fragments hold vulnerabilities and tags only).

### Summary

| Design | UC1 static/dynamic | UC2 domain split | UC3 shared vuln | Branch pain (multi-file on main) | Branch pain (per-branch) | Cost |
|---|---|---|---|---|---|---|
| A imports + concat | yes | yes | no | no | no | large |
| B invocation merge | partial, implicit | partial | no | no | no | large, breaking |
| C override layering | (via A) | (via A) | yes | partial | no | ~2x A |
| D tooling only | no | no | no | yes | yes (best available) | small |
| E two-file split | yes | no | no | no | no | ~0.8x A |

## Key Tension: Duplicate IDs vs Shared Fragments

Issue rule 2 (duplicate IDs across files are errors) directly conflicts with the shared-fragment story of
use case 3 (the same CVE ID in a shared fragment and in a per-document stub carrying the branch-specific
verdict). Sequencing concat-first is the safe direction: every concat-valid document keeps its exact meaning
if an override mechanism is added later, because only previously erroring configurations gain one. Designing
merge-by-ID from the start would bake the contested semantics into the format before anyone needs them. If
overrides ever come, prefer shallow field-level override (a field present in the stub replaces the fragment
field wholesale, an absent field inherits, no list merging): deterministic, explainable, and round-trippable
by the canonical writer.

## Recommendation

Phased, matching the project values (pain relief through deterministic tooling first, then a git-native,
minimal, versioned format change).

- **Phase 0, prerequisites (worth doing regardless).** Fail on unknown YAML fields (`local-issues/03`; this
  is also the safety ratchet for all future schema evolution, since every CLI released without it enlarges
  the installed base that silently mishandles new keys). Fix the copy crash (`local-issues/09`). Resolve
  report filters per file (`local-issues/13`). Add file and entry context to parse errors
  (`local-issues/21`). Fix `V1Mapper.toDto` dropping top-level tags, since every future domain-to-DTO
  writer builds on it.
- **Phase 1, tooling (D).** `modify copy --release <id>` and a read-only `vulnlog diff`. Document in
  `branching-strategy.adoc` that tooling, not imports, is the cross-branch answer, because imports cannot
  cross git branches.
- **Phase 2, imports (A, scoped).** `imports:` in the main file only, depth 1. Fragments carry
  `schemaVersion: "2"` but no `project`, and may hold `vulnerabilities` and `tags` only. Paths are relative
  to the importing file, follow the existing filename rules, and must not be absolute or escape via `..`.
  No imports when reading from stdin. Concatenation with duplicate-ID errors that name both files.
  Cross-file validation with file-qualified findings. Gradle import expansion as declared task inputs in
  the same release. Publish `vulnlog-v2.json` plus a fragment schema. A v2 document without imports stays
  byte-identical to v1 except for the version digit, so migration is opt-in per file.
- **Phase 3, overrides (C-lite), only on demonstrated demand.** Explicit main-over-import shallow override
  on top of phase 2 infrastructure, if shared-finding fragments are still wanted then.

## Open Questions

1. Fragment filename convention: keep `*.vl.yaml` (then the published v2 schema must be a oneOf of document
   and fragment, which makes IDE errors noisier) or introduce a distinct suffix such as `*.vlf.yaml` (clean
   IDE glob association, and shell globs like `validate *.vl.yaml` no longer scoop up fragments). Leaning:
   distinct suffix.
2. Write-routing default: new entries from `modify add <main>` go to the main file with `--into <fragment>`
   as the explicit override, or should a fragment-targeting default exist for the static/dynamic split
   where the main file keeps `vulnerabilities: []`?
3. Is main-over-import override (phase 3) part of the long-term contract? This only affects the wording of
   the phase 2 duplicate-ID error, but it decides whether shared-finding fragments are ever promised.
4. Gradle: automatic import expansion via a configuration-cache-safe `ValueSource` (leaning), or documented
   manual listing with fragment-aware task parsing?
5. Behavior when a fragment is passed directly to `validate`/`fmt`: fragment-local validation with an info
   note, or a hard error pointing at the importing main file?
