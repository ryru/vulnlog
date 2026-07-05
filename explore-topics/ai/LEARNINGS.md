# LEARNINGS.md

Dated notes from AI agent sessions: corrections, gotchas, and decisions not yet
stable enough for `AGENTS.md`. Newest first. Keep entries to one or two lines:
what happened and why it matters. Promote stable entries to `AGENTS.md`; delete
entries that stop being true.

## Entries

- 2026-07-05: `V1Mapper.toDto` is a lossy domain-to-DTO path; round-tripping
  domain to DTO to YAML can silently drop fields. Check field coverage when
  touching the mapping.
- 2026-07-05: The GraalVM native image needs reflection config for the Jackson
  DTO classes; a missing entry only fails at runtime in the native binary, not
  in JVM tests.
- 2026-07-05: All writing commands rewrite `vulnlog.yaml` canonically via
  `CanonicalYaml`; YAML comments are not preserved by design.
- 2026-07-05: Local docs builds read from a sibling checkout at `../vulnlog`
  (see `antora-local-playbook.yml`); adjust the playbook URL if the layout differs.
