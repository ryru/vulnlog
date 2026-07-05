---
name: "Bug Report"
about: Report something that's broken or not working as expected in Vulnlog.
title: "[Bug] JSON schema claims the analysis field changes the state, but state only derives from verdict and resolution"
labels: bug
assignees: ''
---

### Describe the Bug

The schema description of `analysis` says: "Presence of this field moves the entry out
of the 'under investigation' state". That is not what the code does, and it contradicts
the project's own documentation: vulnerability-states.adoc derives the state only from
`verdict` and `resolution` ("If no verdict is recorded, state is under investigation"),
and `findWorkState` implements exactly that. An entry with an `analysis` but no
`verdict` stays under investigation.

Editors surface these descriptions as inline help, so the wrong sentence actively
misleads users writing the YAML.

Where does the problem occur:

- [ ] CLI
- [x] YAML format
- [ ] Suppression output

### Steps to Reproduce

1. Read the `analysis` description in `schema/v1/defs/vulnerability.json` (also compiled
   into `schema/vulnlog-v1.json`).
2. Compare with docs/modules/ROOT/pages/vulnerability-states.adoc and
   `findWorkState` in `Reporting.kt`.

### Expected Behavior

Schema description matches the implemented rule, for example: "Free-text analysis and
rationale for the triage decision. The state is derived from 'verdict' and 'resolution',
not from this field."

### Actual Behavior

The schema promises a state change that never happens.

### Environment (optional)

- **Version:** built from `review` branch, commit f652565

### Additional Context (optional)

Pure documentation fix in the two schema JSON files. Good first issue.
