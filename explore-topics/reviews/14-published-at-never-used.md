---
name: "Bug Report"
about: Report something that's broken or not working as expected in Vulnlog.
title: "[Bug] Docs promise published_at influences state and copy, but the field is never read"
labels: bug
assignees: ''
---

### Describe the Bug

`releases[].published_at` is parsed and written back, but no logic ever reads it. Two
documented behaviors do not match the code:

1. vulnerability-states.adoc says: with `--release X`, "a resolution only counts when its
   target release *ships* at-or-before X" and "a resolution pointing at a later or
   *unpublished* release is ignored". The code (`findWorkState`) only checks membership
   in the filtered release set; publication dates play no role. A resolution pointing at
   an unpublished release is counted as resolved.
2. The `modify copy` CLI help says the copied entry's release is set to "the latest
   *published* release". The code takes the last release in file order, published or not.
   (The cli-copy.adoc page describes it correctly as "the last release in the target's
   list". The help text also has a typo: "to past vulnerabilities into".)

Where does the problem occur:

- [x] CLI
- [ ] YAML format
- [ ] Suppression output
- [x] Documentation

### Steps to Reproduce

1. Define releases `1.0.0` (with `published_at`) and `2.0.0` (without, so unpublished).
2. Add an entry with `releases: [1.0.0, 2.0.0]`, `verdict: affected`, `severity: high`,
   and `resolution: { in: 2.0.0 }`.
3. Run `vulnlog report file.vl.yaml --release 2.0.0`.
4. The entry is shown as `resolved`, although `2.0.0` has not shipped. Per the docs, the
   resolution should be ignored and the entry shown as `open`.

### Expected Behavior

Docs and behavior agree. Either implement the documented rule (a resolution only counts
when its release has a `published_at` on or before the reference date) or reword the
docs and the copy help text to describe the actual list-order semantics.

### Actual Behavior

`published_at` is decorative. Two docs statements and one CLI help text describe
behavior that does not exist.

### Environment (optional)

- **Version:** built from `review` branch, commit f652565

### Additional Context (optional)

Smallest honest fix: align the wording (docs + `CopyCommand` help, including the
past/paste typo) with the implemented behavior, and track "respect published_at" as a
separate feature decision.
