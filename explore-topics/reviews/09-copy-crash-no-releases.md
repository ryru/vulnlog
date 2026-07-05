---
name: "Bug Report"
about: Report something that's broken or not working as expected in Vulnlog.
title: "[Bug] modify copy crashes with a stack trace when the target file has no releases"
labels: bug
assignees: ''
---

### Describe the Bug

`vulnlog modify copy` rewrites the copied entry's `releases` to the target's last
release. When the target defines no releases (which is exactly what `vulnlog init`
produces), `destination.releases.last()` throws `NoSuchElementException` and the user
gets a raw stack trace.

Where does the problem occur:

- [x] CLI
- [ ] YAML format
- [ ] Suppression output

### Steps to Reproduce

1. `vulnlog init --organization A --name B --author C -o fresh.yaml`
   (or any file with `releases: []`)
2. `vulnlog modify copy source.vl.yaml fresh.yaml --vuln-id CVE-2021-44228`

### Expected Behavior

A clear error such as:

```
Error: fresh.yaml defines no releases; add a release before copying entries into it.
```

Exit code 1, no stack trace. (Alternatively: copy the entry with an empty `releases`
list, like `modify add` does when the target has no releases.)

### Actual Behavior

```
Exception in thread "main" java.util.NoSuchElementException: List is empty.
	at dev.vulnlog.lib.core.CopyKt.copyVulnerabilities(Copy.kt:46)
	at dev.vulnlog.cli.shell.CopyCommand.run(CopyCommand.kt:71)
	...
```

### Environment (optional)

- **Version:** built from `review` branch, commit f652565

### Additional Context (optional)

The Gradle `VulnlogCopyTask` uses the same code path and fails the same way. Deciding
between "reject with message" and "copy with empty releases" is the main design point;
`modify add` already chose the second option for consistency.
