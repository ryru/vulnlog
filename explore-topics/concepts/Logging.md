# Logging Concept

Status: proposal, 2026-07-04. Covers the CLI, the Gradle plugin, and the lib module.

## Current state

- The CLI has no logging at all. Everything the user sees goes through Clikt's
  `echo`, split between stdout and stderr. Unexpected exceptions surface as raw
  stack traces (issue #195).
- The Gradle plugin uses the Gradle logger (`lifecycle`, `warn`). This is the
  correct mechanism for Gradle and stays.
- `lib` core code neither logs nor prints. It is deterministic and returns
  result types. This is a feature, not a gap.
- `-v` is unused today. The root command only binds `--version` (long form via
  `versionOption`), so the short flag is free.

## Two channels, not one

The concept separates two things that logging frameworks tend to blur:

1. User output: the product of a command (report content, suppression files,
   formatted YAML) plus short status and error messages. Specified in
   `Output-Messages.md`. Not logging.
2. Diagnostics: optional detail about what the tool did and why, for debugging
   a run. Off by default, enabled by flags. This document.

Diagnostics always go to stderr. Stdout is reserved for command output so that
`vulnlog suppress --output - > .trivyignore.yaml` stays safe at any verbosity.
There is no log file. The CLI is a short-lived process; users who want a file
redirect stderr.

## Flags

Global options on the root `vulnlog` command, inherited by all subcommands:

| Flag | Effect |
|------|--------|
| (none) | Errors, warnings, and one status line per action. Today's behavior. |
| `-v`, `--verbose` | Adds diagnostic lines prefixed `verbose:`. |
| `-vv`, `--debug` | Adds `debug:` lines and full stack traces on unexpected errors. |
| `-q`, `--quiet` | Suppresses status lines and `info:`. Errors and warnings always print. |

`-v` is a counted flag (Clikt `counted()`), so `-vv` needs no separate
implementation. `--debug` is an alias for `-vv`. `-q` and `-v` together is an
error. No environment variable in the first iteration; if CI use shows a need,
`VULNLOG_VERBOSITY` can be added later without breaking anything.

## What gets logged at which level

Verbose answers "what did the tool process": one line per boundary event.

- Per input file: path, detected schema version, entry counts
  (releases, tags, vulnerabilities).
- Filter resolution: which releases and tags a `--release`/`--tag` filter
  expanded to.
- Per output file: path, format, number of entries written.
- Every entry excluded from an output, with the reason. This makes the silent
  drops of issue #198 visible: `verbose: skipped CVE-2026-1234 for .snyk: no
  snyk vuln_ids and id is not a SNYK id`.

Debug answers "why did the tool decide that": suppression eligibility per
entry and reporter, canonical rewrite decisions, timing per phase, and stack
traces for every caught exception. Debug may be noisy; verbose must stay
readable for a file with a few hundred entries.

Format: `verbose: <message>` and `debug: <message>`, plain ASCII, no
timestamps. A short-lived CLI gains nothing from timestamps, and their absence
keeps output diffable in bug reports.

## Library choice: none

Recommendation: no logging framework. A small hand-rolled sink in `lib`:

```kotlin
fun interface DiagnosticSink {
    fun accept(event: DiagnosticEvent)
}

data class DiagnosticEvent(val level: DiagnosticLevel, val message: String)

enum class DiagnosticLevel { VERBOSE, DEBUG }
```

The CLI installs a sink that filters by the `-v` count and writes to stderr
through `echo`. The Gradle plugin installs a sink that maps VERBOSE to
`logger.info` and DEBUG to `logger.debug`, so `gradle --info` and `--debug`
work as Gradle users expect with no extra flags. The sink is carried in the
Clikt context (`currentContext.obj`) so subcommands do not thread it manually.

Rationale against the alternatives:

- SLF4J + slf4j-simple or Logback: service-loader and reflection machinery is
  exactly what the GraalVM native image build wants to avoid; configuration
  files and appenders solve server problems (rotation, MDC, async) that a CLI
  does not have; and the Gradle plugin would then log past Gradle's own log
  level handling.
- kotlin-logging: a facade over SLF4J, same objections plus one more artifact.
- java.util.logging: native-image safe but its configuration model and default
  formatting fight the "quiet by default, stderr only" goal for no gain.

A `fun interface` and an enum cost nothing at native-image build time, add no
dependency to audit in Vulnlog's own vulnlog.yaml, and are trivially testable.

## Core stays clean

Core code must not receive a sink as a convenience for skipping result
modelling. The order of preference:

1. Return richer result types. Example: the suppression pipeline should return
   included and excluded entries with exclusion reasons; the shell decides
   whether to render them as verbose lines or warnings. This also fixes the
   root of issue #198 instead of papering over it.
2. Only where a result type is impractical (streaming parse steps), a core
   function may accept a `DiagnosticSink` parameter, defaulting to a no-op.

This keeps core deterministic and keeps the decision of what is worth showing
in the shell layer, where it belongs.

## Error handling interaction

With the sink in place, the top-level exception handling becomes uniform:
catch unexpected exceptions in one place, print a single `error:` line
(see `Output-Messages.md`), and print the stack trace only at `-vv`. This
subsumes the per-command try/catch blocks and resolves issue #195 in the same
change.

## Related issues

- #195: YAML syntax errors crash the CLI with a raw stack trace. Stack traces
  move behind `-vv`.
- #198: suppress silently drops entries. Exclusions become visible at `-v` and
  the core returns them explicitly.
- #208: parse errors should name the entry and report all problems at once.
  Complementary; better errors reduce the need for diagnostics.
- No existing issue asks for `--verbose` itself; this concept is new ground.

## Suggested implementation order

1. Add `DiagnosticSink` to lib, no-op default, wire the Clikt context object
   and the global flags.
2. Central exception handler with `-vv` stack traces (closes #195).
3. Verbose events for file input/output and filter resolution.
4. Rework suppression pipeline to return exclusions (closes #198), render at
   `-v`.
