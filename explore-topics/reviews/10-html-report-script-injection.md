---
name: "Bug Report"
about: Report something that's broken or not working as expected in Vulnlog.
title: "[Bug] HTML report breaks (and can execute injected script) when a text field contains </script>"
labels: bug
assignees: ''
---

### Describe the Bug

The HTML report injects the report data as JSON into an inline `<script>` block via
simple string replacement. The JSON is not HTML-escaped, so a `</script>` sequence inside
any text field (analysis, description, comment, project name) terminates the script block
early. Everything after it is parsed as HTML.

Consequences:

1. The report page breaks (data half-rendered or empty).
2. Injected markup runs: the report's CSP allows `script-src 'unsafe-inline'`, so a
   `<script>` tag inside an analysis text executes when someone opens the published
   report. Reports are meant to be published to stakeholders and customers, and analysis
   text often quotes advisories, so this is reachable in practice.

The table rendering itself is safe (it uses `textContent` everywhere); only the JSON
embedding step is affected.

Where does the problem occur:

- [ ] CLI
- [ ] YAML format
- [x] Suppression output
- [x] HTML report

### Steps to Reproduce

1. Set an analysis text to:
   `See vendor advisory </script><script>alert('injected')</script> for details.`
2. `vulnlog report file.vl.yaml -o report.html`
3. Open `report.html`: the alert fires and the report table is broken.

### Expected Behavior

Any text content is data. The report renders it literally and nothing from the YAML can
change the page structure or run as script.

### Actual Behavior

The `</script>` in the analysis text closes the data script block; the following
`<script>` executes.

### Environment (optional)

- **Version:** built from `review` branch, commit f652565

### Additional Context (optional)

Standard fix: escape the serialized JSON for safe embedding in a script context in
`HtmlReportWriter` - after `writeValueAsString`, replace the less-than sign with the
JSON escape sequence backslash-u003c (and greater-than with backslash-u003e, ampersand
with backslash-u0026). These are plain JSON string escapes, so the JavaScript side needs
no change. This also fixes legitimate texts containing `<!--` or `</script>` without any
injection intent.
