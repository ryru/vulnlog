---
name: "Bug Report"
about: Report something that's broken or not working as expected in Vulnlog.
title: "[Bug] YAML syntax errors crash the CLI with a raw stack trace"
labels: bug
assignees: ''
---

### Describe the Bug

When a Vulnlog file has a YAML syntax error (unclosed bracket, bad indentation, tab
character), every command dies with an unhandled `JacksonYAMLParseException` and a full
stack trace instead of the friendly "Parsing of <file> failed:" message.

Cause: `YamlParser.parse` only catches `DatabindException` inside `parseV1`, but the
version detection step (`detectVersion` -> `mapper.readTree`) runs first and throws a
`StreamReadException` subtype that nothing catches. The CLI's `parseInputOrFail` only
handles `IllegalArgumentException` and `IllegalStateException`, so the exception escapes
to the top.

Where does the problem occur:

- [x] CLI
- [x] YAML format
- [ ] Suppression output

### Steps to Reproduce

1. Create a file with broken YAML, for example:

   ```yaml
   schemaVersion: "1"
   project: [unclosed
   ```

2. `vulnlog validate broken.vl.yaml`

### Expected Behavior

```
Parsing of broken.vl.yaml failed:
YAML parse error: while parsing a flow sequence ... expected ',' or ']' (line 2, column 10)
```

Exit code 1, no stack trace.

### Actual Behavior

```
Exception in thread "main" tools.jackson.dataformat.yaml.JacksonYAMLParseException: while parsing a flow sequence
 in reader, line 2, column 10:
    project: [unclosed
    ...
	at tools.jackson...
```

### Environment (optional)

- **Version:** built from `review` branch, commit f652565

### Additional Context (optional)

Fix: in `YamlParser` catch `JacksonException` (the common base) around both `readTree`
and `readValue` and turn it into `ParseResult.Error`. The Gradle tasks go through the
same code path and are equally affected.
