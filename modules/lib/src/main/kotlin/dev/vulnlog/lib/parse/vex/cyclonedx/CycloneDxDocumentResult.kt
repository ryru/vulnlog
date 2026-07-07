// Copyright the Vulnlog contributors
// SPDX-License-Identifier: Apache-2.0

package dev.vulnlog.lib.parse.vex.cyclonedx

import dev.vulnlog.lib.model.Project
import dev.vulnlog.lib.model.ReleaseEntry
import dev.vulnlog.lib.model.vex.VexStatement
import tools.jackson.core.JacksonException
import tools.jackson.databind.JsonNode
import tools.jackson.databind.json.JsonMapper
import tools.jackson.databind.node.ObjectNode
import java.time.Instant

sealed interface CycloneDxDocumentResult {
    /**
     * The existing output already carries the same statements; nothing to write.
     */
    data object Unchanged : CycloneDxDocumentResult

    /**
     * A document to write to the output path.
     */
    data class Document(
        val content: String,
    ) : CycloneDxDocumentResult
}

private data class DocumentIdentity(
    val serialNumber: String,
    val version: Int,
)

private val mapper = JsonMapper.builder().build()

/**
 * Generates the standalone CycloneDX VEX document with identity continuity. A valid existing output
 * keeps its serial number and bumps the version; an absent or invalid one starts a new identity from
 * [newSerialNumber]. When the document equals the existing output apart from `version` and
 * `metadata.timestamp`, nothing is written and the existing file stays untouched.
 */
fun generateCycloneDxDocument(
    project: Project,
    release: ReleaseEntry,
    statements: List<VexStatement>,
    existingOutput: String?,
    newSerialNumber: () -> String,
    timestamp: Instant,
): CycloneDxDocumentResult {
    val existing = existingOutput?.let(::parseBom)
    val identity =
        existing?.let(::priorIdentity)?.let { prior -> prior.copy(version = prior.version + 1) }
            ?: DocumentIdentity(newSerialNumber(), 1)
    val bom = CycloneDxMapper.toDto(project, release, statements, identity.serialNumber, identity.version, timestamp)
    val content = CycloneDxWriter.write(bom)
    if (existing != null && comparableTree(parseBom(content)!!) == comparableTree(existing)) {
        return CycloneDxDocumentResult.Unchanged
    }
    return CycloneDxDocumentResult.Document(content)
}

private fun parseBom(content: String): ObjectNode? =
    try {
        mapper.readTree(content) as? ObjectNode
    } catch (_: JacksonException) {
        null
    }

private fun priorIdentity(bom: ObjectNode): DocumentIdentity? {
    if (bom.path("bomFormat").asString(null) != "CycloneDX") return null
    val serialNumber = bom.path("serialNumber").asString(null) ?: return null
    return DocumentIdentity(serialNumber, bom.path("version").asInt(1))
}

private fun comparableTree(bom: ObjectNode): JsonNode {
    val copy = bom.deepCopy()
    copy.remove("version")
    (copy.get("metadata") as? ObjectNode)?.remove("timestamp")
    return copy
}
