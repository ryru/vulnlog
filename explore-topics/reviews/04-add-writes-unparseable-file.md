---
name: "Bug Report"
about: Report something that's broken or not working as expected in Vulnlog.
title: "[Bug] modify add can write a file that vulnlog itself can no longer parse"
labels: bug
assignees: ''
---

### Describe the Bug

`vulnlog modify add --verdict affected` without `--severity` reports success and rewrites
the target file. The written file then fails to parse in every vulnlog command, because
the parser requires a severity for the verdict `affected`.

The same happens with `--verdict "not affected"` without `--justification`, and with
`--verdict "risk acceptable"` without `--severity`.

The `add` code intentionally skips cross-checking verdict, severity, and justification
("left for the validate command to flag"), but validation never runs on the result:
parsing fails first, so the user is locked out of the file and has to fix it by hand.

Where does the problem occur:

- [x] CLI
- [x] YAML format
- [ ] Suppression output

### Steps to Reproduce

1. `vulnlog modify add file.vl.yaml --vuln-id CVE-2026-0001 --verdict affected`
2. Output: `Added to file.vl.yaml: CVE-2026-0001`
3. `vulnlog validate file.vl.yaml`

### Expected Behavior

Either `add` refuses the incomplete combination up front ("verdict 'affected' requires
--severity"), or the written file stays readable and `validate` flags the inconsistency.

### Actual Behavior

```
Parsing of file.vl.yaml failed:
Parser error: Invalid severity: null
```

Every command (validate, fmt, report, suppress, add) now fails on this file.

### Environment (optional)

- **Version:** built from `review` branch, commit f652565

### Additional Context (optional)

Two independent fixes are possible, and both are worth doing:

1. In `AddCommand`, require `--severity` when the verdict is `affected` or
   `risk acceptable`, and `--justification` when it is `not affected` (clikt can express
   this, or a simple check before writing).
2. As a safety net, `addVulnerabilityToFile` could parse its own output before it is
   written and refuse to produce content that vulnlog cannot read back.
