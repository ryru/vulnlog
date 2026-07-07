// Copyright the Vulnlog contributors
// SPDX-License-Identifier: Apache-2.0

package dev.vulnlog.lib.parse

import dev.vulnlog.lib.model.VulnlogFile
import dev.vulnlog.lib.parse.v1.V1Mapper
import dev.vulnlog.lib.parse.v1.dto.VulnerabilityEntryDto
import dev.vulnlog.lib.parse.v1.dto.VulnlogFileV1Dto
import tools.jackson.databind.ObjectMapper

/**
 * Writes complete Vulnlog documents in the canonical layout: the optional `# $schema:` header, the
 * `---` document start, then the `schemaVersion`, `project`, `tags` (when present), `releases` and
 * `vulnerabilities` sections separated by blank lines, with a blank line before each vulnerability
 * entry. Sections and entries are rendered through [CanonicalYaml].
 *
 * The output is a pure function of the document data plus [includeSchemaHeader]: presentation found
 * in a source file, including YAML comments, is not carried over. The `# $schema:` header is the one
 * exception, kept only when [includeSchemaHeader] says the source had it; see [hasSchemaHeader].
 *
 * Deprecated spellings are not part of the canonical form: every write emits their replacement, so
 * one `vulnlog fmt` migrates a file in place.
 */
object YamlWriter {
    fun write(
        file: VulnlogFile,
        mapper: ObjectMapper,
        includeSchemaHeader: Boolean = true,
    ): String = renderCanonicalDocument(V1Mapper.toDto(file), mapper, includeSchemaHeader)

    fun renderCanonicalDocument(
        dto: VulnlogFileV1Dto,
        mapper: ObjectMapper,
        includeSchemaHeader: Boolean = true,
    ): String {
        val migrated = migrateDeprecatedTokens(dto)
        val sections =
            buildList {
                add(CanonicalYaml.renderSection("schemaVersion", migrated.schemaVersion, mapper).trimEnd())
                add(CanonicalYaml.renderSection("project", migrated.project, mapper).trimEnd())
                migrated.tags?.let { add(CanonicalYaml.renderSection("tags", it, mapper).trimEnd()) }
                add(CanonicalYaml.renderSection("releases", migrated.releases, mapper).trimEnd())
                add(vulnerabilitiesSection(migrated.vulnerabilities, mapper))
            }
        val header = if (includeSchemaHeader) schemaHeader(migrated.schemaVersion) + "\n" else ""
        return header + "---\n" + sections.joinToString("\n\n") + "\n"
    }

    private fun migrateDeprecatedTokens(dto: VulnlogFileV1Dto): VulnlogFileV1Dto =
        dto.copy(
            vulnerabilities =
                dto.vulnerabilities.map { entry ->
                    if (entry.verdict == "risk acceptable") {
                        entry.copy(verdict = "affected", disposition = "wont-fix")
                    } else {
                        entry
                    }
                },
        )

    fun schemaHeader(schemaVersion: String): String =
        "# \$schema: https://vulnlog.dev/schema/vulnlog-v${schemaVersion.substringBefore('.')}.json"

    private fun vulnerabilitiesSection(
        entries: List<VulnerabilityEntryDto>,
        mapper: ObjectMapper,
    ): String =
        if (entries.isEmpty()) {
            CanonicalYaml.renderSection("vulnerabilities", entries, mapper).trimEnd()
        } else {
            "vulnerabilities:\n\n" +
                entries.joinToString("\n\n") { CanonicalYaml.renderEntryListItem(it, mapper) }
        }
}
