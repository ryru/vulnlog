---
name: "Bug Report"
about: Report something that's broken or not working as expected in Vulnlog.
title: "[Bug] Misspelled or unknown YAML fields pass validation and are silently deleted on rewrite"
labels: bug
assignees: ''
---

### Describe the Bug

Unknown fields in a Vulnlog file are accepted without any message. `vulnlog validate`
reports "Validation OK", and every rewriting command (`fmt`, `modify add`, `modify copy`)
silently deletes them.

This hits users who make a typo: `analysed_at` instead of `analyzed_at`, `verdikt`,
a wrongly indented key, and so on. The typo is not flagged, the data the user wrote is
treated as absent, and the next `fmt` erases it from the file for good.

The cause is a Jackson 3 default change: `FAIL_ON_UNKNOWN_PROPERTIES` is now disabled by
default, and the YAML mapper in `YamlMapperFactory` does not re-enable it.

Where does the problem occur:

- [x] CLI
- [x] YAML format
- [ ] Suppression output

### Steps to Reproduce

1. Add `analysed_at: 2026-01-01` (note the misspelling) and `made_up_field: some data`
   to a vulnerability entry.
2. Run `vulnlog validate file.vl.yaml` -> "Validation OK".
3. Run `vulnlog fmt file.vl.yaml`.
4. Both fields are gone from the file.

### Expected Behavior

Unknown fields are rejected (parse error naming the field and entry), or at minimum
reported as a validation error, before any command rewrites the file.

### Actual Behavior

`validate` says OK, `fmt` says "Formatted:" and deletes the unknown fields without
any warning. Silent data loss in a hand-edited file.

### Environment (optional)

- **Version:** built from `review` branch, commit f652565

### Additional Context (optional)

Fix: enable `DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES` in `createYamlMapper()`
and turn the resulting exception into a friendly parse error. All DTOs are 1:1 images of
the schema, so any unknown key is a user mistake.
