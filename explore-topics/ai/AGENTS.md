# AGENTS.md

Instructions for AI agents working on Vulnlog. Read `LEARNINGS.md` next: it holds
recent knowledge not yet promoted into this file.

## Project

Vulnlog records vulnerability analysis as code: each finding's analysis and verdict
is stored once in a YAML file in git, and Vulnlog generates scanner suppressions and
reports from it. Kotlin, built with Gradle.

- `modules/lib`: domain logic. `core` is deterministic and idempotent; side effects live in `shell`.
- `modules/cli-app`: the CLI.
- `modules/gradle-plugin`: Gradle integration.
- Internals: `devdoc/`. Contributor workflow: `CONTRIBUTING.md`.

## Commands

- Build and test: `./gradlew build`
- All checks: `./gradlew check`
- Format before committing: `./gradlew spotlessApply ktlintFormat`
- Run the CLI: `./gradlew run --args='--version'`

## Rules

- Never commit to main. Every change reaches main through a pull request.
- Keep repository files ASCII-only. No em dashes, ellipses, or smart quotes.
- Never edit `CHANGELOG.md` by hand; git-cliff generates it.
- Put logic in `core` with unit tests. Core code stays deterministic and idempotent.
- Vulnlog follows the data-oriented programming paradigm as described in
  https://www.manning.com/books/data-oriented-programming-in-java: wrap
  primitives in domain types; do not pass bare strings around.
- Write self-documenting code. Keep comments terse and few.
- Keep the YAML schema minimal: never add data that can be looked up online
  (CVSS scores, CWE, advisory links). Enrichment joins at generation time.
- Commits follow Conventional Commits with a DCO sign-off (`git commit -s`).
  Subject: 50 chars max, imperative mood. See `CONTRIBUTING.md`.

## Docs

User docs are AsciiDoc under `docs/`, built with Antora (`./gradlew docsBuild`).
Write formal but friendly prose: clean, compact, technical.

## Learnings

When the user corrects you, or a non-obvious gotcha costs you time, append a dated
entry to `LEARNINGS.md`. Stable entries get promoted here; stale ones get deleted.
