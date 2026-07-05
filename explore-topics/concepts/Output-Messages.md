# Output Message Concept

Status: proposal, 2026-07-04. Defines how the Vulnlog CLI talks to users:
wording, structure, colors, and behavior in CI. Diagnostics (`-v`, `-vv`) are
specified in `Logging.md`.

## Current state

The messages grew per command and it shows:

- Three patterns for the same idea: `Vulnlog file created at: ...`,
  `Report written to: ...`, `Suppression file created at: ...`.
- Mixed severity markers: `Error: ...` in some commands, `[ERROR] path: msg`
  from the validation renderer, bare `e.message` elsewhere.
- `renderValidation` prints `OK <em dash> no issues found.` with a literal em
  dash, violating the repo's ASCII-only rule.
- Summary lines use the `2 error(s)` crutch.
- Internal representations leak: `Release(value=1.0.0)` (issue #203).
- Every command starts by printing a blank line to stderr
  (`printOutputSeparator`), which garbles piped stderr in CI logs.
- No color anywhere, although Mordant already ships with the Clikt artifact in
  use.

## Principles

1. Stdout is data, stderr is conversation. Report content, suppression files,
   and formatted YAML go to stdout only when `-` is the target; everything
   addressed to a human goes to stderr. This is already mostly true and
   becomes a hard rule. The startup blank line is removed.
2. Quiet success. A command that worked prints one status line per action and
   nothing else. No banners, no separators.
3. Errors say three things: what failed, where, and what to do next. If the
   third part is known, it is worth a second line.
4. One vocabulary. The same event is always worded the same way in the CLI and
   in the Gradle plugin (which reuses the shared formatter functions from lib).

## Language and tone

- English, sentence case, plain ASCII. No emoji, no Unicode symbols, no
  exclamation marks. This matches the docs voice: formal but friendly.
- Present or simple past, active where possible: `Created vulnlog.yaml`, not
  `The file has been created`.
- Never print internal representations. Domain types render through their
  value (`1.0.0`), never through `toString()` of a data class (issue #203).
- User-supplied values are quoted with single quotes: `release '9.9.9' is not
  defined`.

## Message grammar

Status lines (stderr, suppressed by `-q`):

```
<Verb>: <path or subject>
```

Examples replacing today's zoo: `Created: vulnlog.yaml`,
`Wrote: reports/report.html`, `Formatted: vulnlog.yaml`,
`Unchanged: vulnlog.yaml`, `Copied: 3 entries to next/vulnlog.yaml`.
The columnar form is grep- and eye-friendly across multi-file runs.

Findings and errors (stderr, never suppressed):

```
<severity>: <file>[: <location>]: <message>
  hint: <next step, when known>
```

Severity prefixes are lowercase `error:`, `warning:`, `info:`, matching the
rustc/cargo/clang convention users already know. The bracketed
`[ERROR]`/`WARN ` forms are retired. Location uses the YAML path notation the
validator already has: `vulnlog.yaml: vulnerabilities[3].resolution.in:
release '9.9.9' is not defined`.

Summary line after findings, with real plurals:

```
2 errors, 1 warning
```

Prompts: only when stdin is a TTY. In a pipe or CI the command must fail with
an explanatory error instead of hanging or assuming yes. This is the general
rule behind fixing issue #202 (`init` overwriting without asking).

## Color

Mordant is already on the classpath via Clikt, so color costs no new
dependency. Usage stays minimal and semantic:

| Element | Style |
|---------|-------|
| `error:` prefix | red, bold |
| `warning:` prefix | yellow |
| `hint:` prefix | cyan |
| Status verb (`Created`, `Wrote`) | green |
| Counts in summary lines | bold |
| Paths, values, everything else | unstyled |

Color never carries information on its own; stripped output reads identically.
Rules for when color is active:

- On when the stream is a TTY, off when piped or redirected.
- `NO_COLOR` (any value) forces off; `FORCE_COLOR`/`CLICOLOR_FORCE` forces on.
  Mordant implements this detection already; the CLI just must not bypass it.
- No `--no-color` flag initially; the environment conventions cover the need.

## CI behavior

- Color: off by default because there is no TTY. CI systems that render ANSI
  (GitHub Actions does) can set `FORCE_COLOR=1` themselves; Vulnlog does not
  special-case CI vendors in the first iteration.
- Exit codes are the machine interface and become documented API: 0 success,
  1 general error, 2 validation error, 3 format error, 4 file not found,
  5 invalid flag value (the existing `ExitCode` enum). The docs get a table;
  the ordinal-based mapping in code should move to explicit values so a
  reordering can never silently change the contract.
- Findings stay one per line, stable in shape, so `grep '^error:'` works.
- Later, opt-in: `--format github` emitting workflow commands
  (`::error file=vulnlog.yaml::...`) so findings annotate pull requests, and
  `--format json` for tooling. Both are additive and out of scope for the
  first pass; the grammar above is designed so they can be generated from the
  same finding data.

The Gradle plugin does not emit ANSI itself; it maps findings to `logger.warn`
and `logger.error` and lets Gradle handle presentation. Message wording comes
from the same shared formatters so CLI and plugin never drift.

## Migration inventory

| Today | Becomes |
|-------|---------|
| `Vulnlog file created at: <abs path>` | `Created: <path>` |
| `Report written to: <abs path>` | `Wrote: <path>` |
| `Suppression file created at: <abs path>` | `Wrote: <path>` |
| `Formatted: <path>` | unchanged |
| `Already formatted: <path>` | `Unchanged: <path>` |
| `Can be reformatted: <path>` | `warning: <path>: not canonically formatted` |
| `Validation OK` | `Validation OK` (kept, printed to stderr) |
| `OK <em dash> no issues found.` | `OK: no issues found` |
| `[ERROR] <path>: <msg>` | `error: <file>: <path>: <msg>` |
| `Error: <msg>` | `error: <msg>` |
| `<n> error(s), <n> warning(s)` | `<n> errors, <n> warning` (real plurals) |
| leading blank line on stderr | removed |

Paths print as given by the user (relative stays relative); absolute paths
appear only when the tool chose the location itself.

## Related issues

- #203: duplicate release/tag findings print `Release(value=1.0.0)`.
- #195: raw stack traces; the `error:` grammar plus `Logging.md` handling.
- #208: parse errors should name the entry and report all problems at once;
  the finding grammar gives those errors their shape.
- #202: `init` overwrites without asking; covered by the TTY prompt rule.
- #191: fail early on invalid `modify add` flag combinations; the errors
  produced should use the `error:`/`hint:` form.
